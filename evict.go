package session_to_jwt

import (
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(SessionToJwtEvict{})
	httpcaddyfile.RegisterHandlerDirective("session_to_jwt_evict", parseEvictCaddyfile)
}

// SessionToJwtEvict verwijdert de gecachte JWT voor de meegestuurde sessie-cookie.
// Bedoeld als INTERN endpoint dat de Next-server bij uitloggen aanroept; beschermd
// met hetzelfde shared secret. Niet via de publieke ingress exposen.
type SessionToJwtEvict struct {
	SharedSecret string `json:"shared_secret"`
	CookieName   string `json:"cookie_name"`

	logger *zap.Logger
}

func (SessionToJwtEvict) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.session_to_jwt_evict",
		New: func() caddy.Module { return new(SessionToJwtEvict) },
	}
}

func (m *SessionToJwtEvict) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()
	if m.CookieName == "" {
		m.CookieName = "better-auth.session_token"
	}
	return nil
}

func (m *SessionToJwtEvict) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	if m.SharedSecret == "" || r.Header.Get("x-proxy-secret") != m.SharedSecret {
		w.WriteHeader(http.StatusForbidden)
		return nil
	}
	if cookie, err := r.Cookie(m.CookieName); err == nil && cookie.Value != "" {
		SharedCache().Delete(cookie.Value)
	}
	// Idempotent: altijd 204, ook als er niets te verwijderen viel.
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (m *SessionToJwtEvict) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "shared_secret":
				if !d.Args(&m.SharedSecret) {
					return d.ArgErr()
				}
			case "cookie_name":
				if !d.Args(&m.CookieName) {
					return d.ArgErr()
				}
			default:
				return d.Errf("onbekende optie: %s", d.Val())
			}
		}
	}
	return nil
}

func parseEvictCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m SessionToJwtEvict
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return &m, err
}

var (
	_ caddy.Provisioner           = (*SessionToJwtEvict)(nil)
	_ caddyhttp.MiddlewareHandler = (*SessionToJwtEvict)(nil)
	_ caddyfile.Unmarshaler       = (*SessionToJwtEvict)(nil)
)
