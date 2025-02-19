package session_to_jwt

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strconv"
	"sync"
	"time"

	"github.com/bsm/redislock"
	"github.com/redis/go-redis/v9"
)

type RedisSessionTokenData struct {
	SessionID       string    `json:"session_id"`
	SessionExpiryDt time.Time `json:"session_expiry_dt"`
	Token           []byte    `json:"token"`
	TokenExpiryDt   time.Time `json:"token_expiry_dt"`
	TokenEncrypted  int       `json:"token_encrypted"`
}

//// create a new SessionTokenMiddleware struct with default values
//func New() *SessionTokenMiddleware {
//
//	rs := SessionTokenMiddleware{
//		ClientType:  defaultClientType,
//		Host:        []string{defaultHost},
//		Port:        []string{defaultPort},
//		DB:          defaultDb,
//		KeyPrefix:   defaultKeyPrefix,
//		TlsEnabled:  defaultTLS,
//		TlsInsecure: defaultTLSInsecure,
//	}
//	return &rs
//}

// Initilalize Redis client and locker
func (m *SessionTokenMiddleware) initRedisClient(ctx context.Context) error {

	// Configure options for all client types
	clientOpts := redis.UniversalOptions{
		Addrs:      m.Address,
		MasterName: m.MasterName,
		Username:   m.Username,
		Password:   m.Password,
		DB:         m.DB,
	}

	// Configure timeout values if defined
	if m.Timeout != "" {
		// Was already sanity-checked in UnmarshalCaddyfile
		timeout, _ := strconv.Atoi(m.Timeout)
		clientOpts.DialTimeout = time.Duration(timeout) * time.Second
		clientOpts.ReadTimeout = time.Duration(timeout) * time.Second
		clientOpts.WriteTimeout = time.Duration(timeout) * time.Second
	}

	// Configure cluster routing options
	if m.RouteByLatency || m.RouteRandomly {
		clientOpts.RouteByLatency = m.RouteByLatency
		clientOpts.RouteRandomly = m.RouteRandomly
	}

	// Configure TLS support if enabled
	if m.TlsEnabled {
		clientOpts.TLSConfig = &tls.Config{
			InsecureSkipVerify: m.TlsInsecure,
		}

		if len(m.TlsServerCertsPEM) > 0 && len(m.TlsServerCertsPath) > 0 {
			return fmt.Errorf("Cannot specify TlsServerCertsPEM alongside TlsServerCertsPath")
		}

		if len(m.TlsServerCertsPEM) > 0 || len(m.TlsServerCertsPath) > 0 {
			certPool := x509.NewCertPool()
			pem := []byte(m.TlsServerCertsPEM)

			if len(m.TlsServerCertsPath) > 0 {
				var err error
				pem, err = os.ReadFile(m.TlsServerCertsPath)
				if err != nil {
					return fmt.Errorf("Failed to load PEM server certs from file %s: %v", m.TlsServerCertsPath, err)
				}
			}

			if !certPool.AppendCertsFromPEM(pem) {
				return fmt.Errorf("Failed to load PEM server certs")
			}

			clientOpts.TLSConfig.RootCAs = certPool
		}
	}

	// Create appropriate Redis client type
	if m.ClientType == "failover" && clientOpts.MasterName != "" {

		// Create new Redis Failover Cluster client
		clusterClient := redis.NewFailoverClusterClient(clientOpts.Failover())

		// Test connection to the Redis cluster
		err := clusterClient.ForEachShard(ctx, func(ctx context.Context, shard *redis.Client) error {
			return shard.Ping(ctx).Err()
		})
		if err != nil {
			return err
		}
		m.client = clusterClient

	} else if m.ClientType == "cluster" || len(clientOpts.Addrs) > 1 {

		// Create new Redis Cluster client
		clusterClient := redis.NewClusterClient(clientOpts.Cluster())

		// Test connection to the Redis cluster
		err := clusterClient.ForEachShard(ctx, func(ctx context.Context, shard *redis.Client) error {
			return shard.Ping(ctx).Err()
		})
		if err != nil {
			return err
		}
		m.client = clusterClient

	} else {

		// Create new Redis simple standalone client
		m.client = redis.NewClient(clientOpts.Simple())

		// Test connection to the Redis server
		err := m.client.Ping(ctx).Err()
		if err != nil {
			return err
		}
	}

	// Create new redislock client
	m.locker = redislock.New(m.client)
	m.locks = &sync.Map{}
	return nil
}

func (m *SessionTokenMiddleware) Store(ctx context.Context, sessionId string, token []byte, sessionExpiryDt time.Time, tokenExpiryDt time.Time) error {

	var encryptionFlag = 0

	// Encrypt value if encryption enabled
	if m.EncryptionKey != "" {
		encryptedValue, err := m.encrypt(token)
		if err != nil {
			return fmt.Errorf("Unable to encrypt value for %s: %v", sessionId, err)
		}
		token = encryptedValue
		encryptionFlag = 1
	}

	sd := &RedisSessionTokenData{
		SessionID:       sessionId,
		SessionExpiryDt: sessionExpiryDt,
		Token:           token,
		TokenExpiryDt:   tokenExpiryDt,
		TokenEncrypted:  encryptionFlag,
	}

	jsonValue, err := json.Marshal(sd)
	if err != nil {
		return fmt.Errorf("Unable to marshal value for %s: %v", sessionId, err)
	}

	var prefixedKey = m.prefixKey(sessionId)

	// Store the key value in the Redis database
	if err := m.client.Set(ctx, prefixedKey, jsonValue, 0).Err(); err != nil {
		return fmt.Errorf("Unable to set value for sessionId %s: %v", sessionId, err)
	}

	return nil
}

func (m *SessionTokenMiddleware) Load(ctx context.Context, sessionId string) (*RedisSessionTokenData, error) {

	var sd *RedisSessionTokenData
	var token []byte
	var err error

	sd, err = m.loadStorageData(ctx, sessionId)
	if err != nil {
		return nil, err
	}

	// Decrypt value if encrypted
	if sd.TokenEncrypted > 0 {
		token, err = m.decrypt(sd.Token)
		if err != nil {
			return nil, fmt.Errorf("Unable to decrypt value for %s: %v", sessionId, err)
		}
		sd.Token = token
	}

	// store last usage (for progressive session expiration)
	m.client.Set(ctx, m.prefixLastUsage(sessionId), time.Now(), 0)

	return sd, nil
}

func (m *SessionTokenMiddleware) Delete(ctx context.Context, sessionId string) error {

	var prefixedKey = m.prefixKey(sessionId)

	if err := m.client.Del(ctx, prefixedKey).Err(); err != nil {
		return fmt.Errorf("Unable to remove %s: %v", prefixedKey, err)
	}

	return nil
}

func (m *SessionTokenMiddleware) Exists(ctx context.Context, sessionId string) bool {

	// Redis returns a count of the number of keys found
	exists := m.client.Exists(ctx, m.prefixKey(sessionId)).Val()

	return exists > 0
}

func (m *SessionTokenMiddleware) Lock(ctx context.Context, name string) error {

	key := m.prefixLock(name)

	for {
		// try to obtain lock
		lock, err := m.locker.Obtain(ctx, key, lockTTL, &redislock.Options{})

		// lock successfully obtained
		if err == nil {
			// store the lock in sync.map, needed for unlocking
			m.locks.Store(key, lock)
			// keep the lock fresh as long as we hold it
			go func(ctx context.Context, lock *redislock.Lock) {
				for {
					// refresh the Redis lock
					err := lock.Refresh(ctx, lockTTL, nil)
					if err != nil {
						return
					}

					select {
					case <-time.After(lockRefreshInterval):
					case <-ctx.Done():
						return
					}
				}
			}(ctx, lock)

			return nil
		}

		// check for unexpected error
		if err != redislock.ErrNotObtained {
			return fmt.Errorf("Unable to obtain lock for %s: %v", key, err)
		}

		// lock already exists, wait and try again until cancelled
		select {
		case <-time.After(lockPollInterval):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (m *SessionTokenMiddleware) Unlock(ctx context.Context, name string) error {

	key := m.prefixLock(name)

	// load and delete lock from sync.Map
	if syncMapLock, loaded := m.locks.LoadAndDelete(key); loaded {

		// type assertion for Redis lock
		if lock, ok := syncMapLock.(*redislock.Lock); ok {

			// release the Redis lock
			if err := lock.Release(ctx); err != nil {
				return fmt.Errorf("Unable to release lock for %s: %v", key, err)
			}
		}
	}
	return nil
}

func (m *SessionTokenMiddleware) prefixKey(key string) string {
	return path.Join(m.KeyPrefix, key)
}

func (m *SessionTokenMiddleware) prefixLock(key string) string {
	return m.prefixKey(path.Join("locks", key))
}

func (m *SessionTokenMiddleware) prefixLastUsage(key string) string {
	return m.prefixKey(path.Join("last_usage_", key))
}

func (m *SessionTokenMiddleware) loadStorageData(ctx context.Context, key string) (*RedisSessionTokenData, error) {

	data, err := m.client.Get(ctx, m.prefixKey(key)).Bytes()
	if data == nil || errors.Is(err, redis.Nil) {
		return nil, fs.ErrNotExist
	} else if err != nil {
		return nil, fmt.Errorf("Unable to get data for %s: %v", key, err)
	}

	sd := &RedisSessionTokenData{}
	if err := json.Unmarshal(data, sd); err != nil {
		return nil, fmt.Errorf("Unable to unmarshal value for %s: %v", key, err)
	}

	return sd, nil
}

func (m *SessionTokenMiddleware) String() string {
	redacted := `REDACTED`
	if m.Password != "" {
		m.Password = redacted
	}
	if m.EncryptionKey != "" {
		m.EncryptionKey = redacted
	}
	strVal, _ := json.Marshal(m)
	return string(strVal)
}

// GetClient returns the Redis client initialized by this storage.
//
// This is useful for other modules that need to interact with the same Redis instance.
// The return type of GetClient is "any" for forward-compatibility new versions of go-redis.
// The returned value must usually be cast to redis.UniversalClient.
func (m *SessionTokenMiddleware) GetClient() any {
	return m.client
}
