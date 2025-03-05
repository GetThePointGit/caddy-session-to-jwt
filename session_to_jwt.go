package session_to_jwt

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/bsm/redislock"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/redis/go-redis/v9"
	"io"
	"sync"

	"go.uber.org/zap"
	"net/http"
	"time"
)

// RedisStorage implements a Caddy storage backend for Redis
// It supports Single (Standalone), Cluster, or Sentinal (Failover) Redis server configurations.
type SessionTokenMiddleware struct {
	GetJwtFromUrl bool   `json:"get_jwt_from_url"`
	JwtUrl        string `json:"jwt_url"`

	// ClientType specifies the Redis client type. Valid values are "cluster" or "failover"
	ClientType string `json:"client_type"`
	// Address The full address of the Redis server. Example: "127.0.0.1:6379"
	// If not defined, will be generated from Host and Port parameters.
	Address []string `json:"address"`
	// Host The Redis server hostname or IP address. Default: "127.0.0.1"
	Host []string `json:"host"`
	// Host The Redis server port number. Default: "6379"
	Port []string `json:"port"`
	// DB The Redis server database number. Default: 0
	DB int `json:"db"`
	// Timeout The Redis server timeout in seconds. Default: 5
	Timeout string `json:"timeout"`
	// Username The username for authenticating with the Redis server. Default: "" (No authentication)
	Username string `json:"username"`
	// Password The password for authenticating with the Redis server. Default: "" (No authentication)
	Password string `json:"password"`
	// MasterName Only required when connecting to Redis via Sentinal (Failover mode). Default ""
	MasterName string `json:"master_name"`
	// KeyPrefix A string prefix that is appended to Redis keys. Default: "caddy"
	// Useful when the Redis server is used by multiple applications.
	KeyPrefix string `json:"key_prefix"`
	// EncryptionKey A key string used to symmetrically encrypt and decrypt data stored in Redis.
	// The key must be exactly 32 characters, longer values will be truncated. Default: "" (No encryption)
	EncryptionKey string `json:"encryption_key"`
	// Compression Specifies whether values should be compressed before storing in Redis. Default: false
	TlsEnabled bool `json:"tls_enabled"`
	// TlsInsecure controls whether the client will verify the server
	// certificate. See `InsecureSkipVerify` in `tls.Config` for details. True
	// by default.
	// https://pkg.go.dev/crypto/tls#Config
	TlsInsecure bool `json:"tls_insecure"`
	// TlsServerCertsPEM is a series of PEM encoded certificates that will be
	// used by the client to validate trust in the Redis server's certificate
	// instead of the system trust store. May not be specified alongside
	// `TlsServerCertsPath`. See `x509.CertPool.AppendCertsFromPem` for details.
	// https://pkg.go.dev/crypto/x509#CertPool.AppendCertsFromPEM
	TlsServerCertsPEM string `json:"tls_server_certs_pem"`
	// TlsServerCertsPath is the path to a file containing a series of PEM
	// encoded certificates that will be used by the client to validate trust in
	// the Redis server's certificate instead of the system trust store. May not
	// be specified alongside `TlsServerCertsPem`. See
	// `x509.CertPool.AppendCertsFromPem` for details.
	// https://pkg.go.dev/crypto/x509#CertPool.AppendCertsFromPEM
	TlsServerCertsPath string `json:"tls_server_certs_path"`
	// RouteByLatency Route commands by latency, only used in Cluster mode. Default: false
	RouteByLatency bool `json:"route_by_latency"`
	// RouteRandomly Route commands randomly, only used in Cluster mode. Default: false
	RouteRandomly bool `json:"route_randomly"`

	client redis.UniversalClient
	locker *redislock.Client
	logger *zap.SugaredLogger
	locks  *sync.Map
	ctx    context.Context
}

func init() {
	caddy.RegisterModule(SessionTokenMiddleware{})
	httpcaddyfile.RegisterHandlerDirective("session_to_jwt", parseCaddyfile)
}

// CaddyModule returns the Caddy module information.
func (SessionTokenMiddleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.session_to_jwt",
		New: func() caddy.Module { return new(SessionTokenMiddleware) },
	}
}

func (m SessionTokenMiddleware) parseJwtFromUrl(body io.Reader) (string, time.Time, time.Time, error) {
	// Parse body
	var jwtResponse struct {
		Token         string    `json:"token"`
		TokenExpiry   time.Time `json:"token_expiry"`
		SessionExpiry time.Time `json:"session_expiry"`
	}
	err := json.NewDecoder(body).Decode(&jwtResponse)
	if err != nil {
		return "", time.Time{}, time.Time{}, fmt.Errorf("Error decoding JWT response: %v", err)
	}
	return jwtResponse.Token, jwtResponse.TokenExpiry, jwtResponse.SessionExpiry, nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m SessionTokenMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	sessionID, err := r.Cookie("authjs.session-token")
	if err != nil {
		// Cookie not present, continue to the next handler
		return next.ServeHTTP(w, r)
	}
	m.logger.Info("Session ID found: ", sessionID.Value)
	// Check if session ID is in the map
	m.logger.Info("context ", m.ctx)
	token, err := m.Load(m.ctx, sessionID.Value)
	m.logger.Info("token ", zap.String("token", token))

	if token == "" && err != nil {
		// if no session found, check if jwt can be obtained from url
		if m.GetJwtFromUrl {
			// request jwt from url, using sessionID as a parameter
			resp, err := http.Get(m.JwtUrl + "?session_id=" + sessionID.Value)
			if err != nil {
				m.logger.Error("Error getting JWT from url", zap.Error(err))
				return next.ServeHTTP(w, r)
			}
			// body in format {"token": "jwt", "expiry": "2021-01-01T00:00:00Z", session_expiry: "2021-01-01T00:00:00Z"}
			// parse body
			token, expiryToken, expirySession, err := m.parseJwtFromUrl(resp.Body)
			// transform string to bytes[]
			tokenBytes := []byte(token)

			if err := m.Store(m.ctx, sessionID.Value, tokenBytes, expiryToken, expirySession); err != nil {
				m.logger.Error("Error storing JWT in Redis", zap.Error(err))
			}
		} else {
			// Session ID not found, just continue to the next handler
			m.logger.Info("Session ID not found", zap.String("session_id", sessionID.Value))
			return next.ServeHTTP(w, r)
		}
	}

	if token != "" {
		r.Header.Set("Authorization", "Bearer "+string(token))
		// todo: extend session expiry time if needed

		r = r.WithContext(context.WithValue(r.Context(), "auth_token", token)) // Add token to context
		m.logger.Debug("Authorization header added", zap.String("session_id", sessionID.Value))
	} else {
		// Session ID not found, just continue to the next handler
		m.logger.Info("Session ID not found in map", zap.String("session_id", sessionID.Value))

	}
	return next.ServeHTTP(w, r)
}

// Interface guards
var (
	_ caddy.Provisioner           = (*SessionTokenMiddleware)(nil)
	_ caddy.Validator             = (*SessionTokenMiddleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*SessionTokenMiddleware)(nil)
	_ caddyfile.Unmarshaler       = (*SessionTokenMiddleware)(nil)
)
