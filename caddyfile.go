package session_to_jwt

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"net"
	"strconv"
)

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *SessionTokenMiddleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {

	for d.Next() {

		// Optional Redis client type either "cluster" or "failover"
		if d.NextArg() {
			val := d.Val()
			if val == "cluster" || val == "failover" {
				m.ClientType = val
			} else {
				return d.ArgErr()
			}
		}

		for nesting := d.Nesting(); d.NextBlock(nesting); {
			configKey := d.Val()
			var configVal []string

			if d.NextArg() {
				// configuration item with single parameter
				configVal = append(configVal, d.Val())
			} else {
				// configuration item with nested parameter list
				for nesting := d.Nesting(); d.NextBlock(nesting); {
					configVal = append(configVal, d.Val())
				}
			}
			// There are no valid configurations where configVal slice is empty
			if len(configVal) == 0 {
				return d.Errf("no value supplied for configuraton key '%s'", configKey)
			}

			switch configKey {
			case "address":
				m.Address = configVal
			case "host":
				m.Host = configVal
			case "port":
				m.Port = configVal
			case "db":
				dbParse, err := strconv.Atoi(configVal[0])
				if err != nil {
					return d.Errf("invalid db value: %s", configVal[0])
				}
				m.DB = dbParse
			case "timeout":
				m.Timeout = configVal[0]
			case "username":
				if configVal[0] != "" {
					m.Username = configVal[0]
				}
			case "password":
				if configVal[0] != "" {
					m.Password = configVal[0]
				}
			case "master_name":
				if configVal[0] != "" {
					m.MasterName = configVal[0]
				}
			case "key_prefix":
				if configVal[0] != "" {
					m.KeyPrefix = configVal[0]
				}
			case "encryption_key", "aes_key":
				m.EncryptionKey = configVal[0]
			case "tls_enabled":
				TlsEnabledParse, err := strconv.ParseBool(configVal[0])
				if err != nil {
					return d.Errf("invalid boolean value for 'tls_enabled': %s", configVal[0])
				}
				m.TlsEnabled = TlsEnabledParse
			case "tls_insecure":
				tlsInsecureParse, err := strconv.ParseBool(configVal[0])
				if err != nil {
					return d.Errf("invalid boolean value for 'tls_insecure': %s", configVal[0])
				}
				m.TlsInsecure = tlsInsecureParse
			case "tls_server_certs_pem":
				if configVal[0] != "" {
					m.TlsServerCertsPEM = configVal[0]
				}
			case "tls_server_certs_path":
				if configVal[0] != "" {
					m.TlsServerCertsPath = configVal[0]
				}
			case "route_by_latency":
				routeByLatency, err := strconv.ParseBool(configVal[0])
				if err != nil {
					return d.Errf("invalid boolean value for 'route_by_latency': %s", configVal[0])
				}
				m.RouteByLatency = routeByLatency
			case "route_randomly":
				routeRandomly, err := strconv.ParseBool(configVal[0])
				if err != nil {
					return d.Errf("invalid boolean value for 'route_randomly': %s", configVal[0])
				}
				m.RouteRandomly = routeRandomly
			}
		}
	}
	return nil
}

// Provision module function called by Caddy Server
func (m *SessionTokenMiddleware) Provision(ctx caddy.Context) error {

	m.logger = ctx.Logger().Sugar()

	// Abstract this logic for testing purposes
	err := m.finalizeConfiguration(ctx)
	if err == nil {
		m.logger.Infof("Provision Redis %s storage using address %v", m.ClientType, m.Address)
	}

	return err
}

func (m *SessionTokenMiddleware) finalizeConfiguration(ctx context.Context) error {

	repl := caddy.NewReplacer()

	for idx, v := range m.Address {
		v = repl.ReplaceAll(v, "")
		host, port, err := net.SplitHostPort(v)
		if err != nil {
			return fmt.Errorf("invalid address: %s", v)
		}
		m.Address[idx] = net.JoinHostPort(host, port)
	}
	for idx, v := range m.Host {
		v = repl.ReplaceAll(v, defaultHost)
		addr := net.ParseIP(v)
		_, err := net.LookupHost(v)
		if addr == nil && err != nil {
			return fmt.Errorf("invalid host value: %s", v)
		}
		m.Host[idx] = v
	}
	for idx, v := range m.Port {
		v = repl.ReplaceAll(v, defaultPort)
		_, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("invalid port value: %s", v)
		}
		m.Port[idx] = v
	}
	if m.Timeout = repl.ReplaceAll(m.Timeout, ""); m.Timeout != "" {
		timeParse, err := strconv.Atoi(m.Timeout)
		if err != nil || timeParse < 0 {
			return fmt.Errorf("invalid timeout value: %s", m.Timeout)
		}
	}
	m.MasterName = repl.ReplaceAll(m.MasterName, "")
	m.Username = repl.ReplaceAll(m.Username, "")
	m.Password = repl.ReplaceAll(m.Password, "")
	m.KeyPrefix = repl.ReplaceAll(m.KeyPrefix, defaultKeyPrefix)

	if len(m.EncryptionKey) > 0 {
		m.EncryptionKey = repl.ReplaceAll(m.EncryptionKey, "")
		// Encryption_key length must be at least 32 characters
		if len(m.EncryptionKey) < 32 {
			return fmt.Errorf("invalid length for 'encryption_key', must contain at least 32 bytes: %s", m.EncryptionKey)
		}
		// Truncate keys that are too long
		if len(m.EncryptionKey) > 32 {
			m.EncryptionKey = m.EncryptionKey[:32]
		}
	}

	m.TlsServerCertsPEM = repl.ReplaceAll(m.TlsServerCertsPEM, "")
	m.TlsServerCertsPath = repl.ReplaceAll(m.TlsServerCertsPath, "")

	// TODO: these are non-string fields so they can't easily be substituted at runtime :(
	// m.DB
	// m.Compression
	// m.TlsEnabled
	// m.TlsInsecure
	// m.RouteByLatency
	// m.RouteRandomly

	// Construct Address from Host and Port if not explicitly provided
	if len(m.Address) == 0 {

		var maxAddrs int
		var host, port string

		maxHosts := len(m.Host)
		maxPorts := len(m.Port)

		// Determine max number of addresses
		if maxHosts > maxPorts {
			maxAddrs = maxHosts
		} else {
			maxAddrs = maxPorts
		}

		for i := 0; i < maxAddrs; i++ {
			if i < maxHosts {
				host = m.Host[i]
			}
			if i < maxPorts {
				port = m.Port[i]
			}
			m.Address = append(m.Address, net.JoinHostPort(host, port))
		}
		// Clear host and port values
		m.Host = []string{}
		m.Port = []string{}
	}

	return m.initRedisClient(ctx)
}

func (m *SessionTokenMiddleware) Cleanup() error {
	// Close the Redis connection
	if m.client != nil {
		m.client.Close()
	}

	return nil
}

type storageConfig struct {
	StorageRaw json.RawMessage `json:"storage,omitempty" caddy:"namespace=caddy.storage inline_key=module"`
}

// Validate implements caddy.Validator.
func (m *SessionTokenMiddleware) Validate() error {
	//todo
	return nil
}

// parseCaddyfile unmarshals tokens from h into a new Middleware.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m SessionTokenMiddleware
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}
