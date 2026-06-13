package session_to_jwt

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(SessionToJwt{})
	httpcaddyfile.RegisterHandlerDirective("session_to_jwt", parseCaddyfile)
}

// SessionToJwt ruilt op matched paden de better-auth sessie-cookie in voor een JWT
// (opgevraagd bij een upstream token-endpoint) en zet die als Authorization-header.
type SessionToJwt struct {
	// JwtUrl is het token-endpoint dat een cookie inruilt voor { token, exp }.
	JwtUrl string `json:"jwt_url"`
	// SharedSecret wordt als x-proxy-secret meegestuurd naar JwtUrl.
	SharedSecret string `json:"shared_secret"`
	// CookieName is de naam van de better-auth sessie-cookie. Default: better-auth.session_token.
	CookieName string `json:"cookie_name"`
	// CacheTtlSeconds is de max cache-duur van een JWT. Default: 300 (5 min).
	CacheTtlSeconds int `json:"cache_ttl_seconds"`

	cache  *Cache
	logger *zap.Logger
}

func (SessionToJwt) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.session_to_jwt",
		New: func() caddy.Module { return new(SessionToJwt) },
	}
}

func (m *SessionToJwt) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()
	if m.CookieName == "" {
		m.CookieName = "better-auth.session_token"
	}
	if m.CacheTtlSeconds == 0 {
		m.CacheTtlSeconds = 300
	}
	m.cache = SharedCache()
	return nil
}

type tokenResponse struct {
	Token string `json:"token"`
	Exp   int64  `json:"exp"`
}

func (m *SessionToJwt) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	cookie, err := r.Cookie(m.CookieName)
	if err != nil || cookie.Value == "" {
		// Geen sessie-cookie: laat door zonder JWT (upstream/Hasura valt terug op unauthorized-role).
		return next.ServeHTTP(w, r)
	}

	// 1) Cache?
	if cached, ok := m.cache.Get(cookie.Value); ok {
		r.Header.Set("Authorization", "Bearer "+string(cached))
		return next.ServeHTTP(w, r)
	}

	// 2) Token ophalen bij het Next-endpoint (cookie doorsturen).
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, m.JwtUrl, nil)
	if err != nil {
		m.logger.Error("kon token-request niet maken", zap.Error(err))
		return next.ServeHTTP(w, r)
	}
	req.Header.Set("x-proxy-secret", m.SharedSecret)
	req.Header.Set("Cookie", r.Header.Get("Cookie"))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		m.logger.Error("token-endpoint onbereikbaar", zap.Error(err))
		return next.ServeHTTP(w, r)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// 401/403: geen geldige sessie -> doorlaten zonder JWT.
		return next.ServeHTTP(w, r)
	}
	body, _ := io.ReadAll(resp.Body)
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil || tr.Token == "" {
		m.logger.Error("ongeldige token-response", zap.Error(err))
		return next.ServeHTTP(w, r)
	}

	// 3) Cachen (TTL = min(CacheTtl, tot exp)) en header zetten.
	ttl := m.CacheTtlSeconds
	if tr.Exp > 0 {
		if untilExp := int(tr.Exp - time.Now().Unix()); untilExp > 0 && untilExp < ttl {
			ttl = untilExp
		}
	}
	m.cache.Set(cookie.Value, []byte(tr.Token), ttl)
	r.Header.Set("Authorization", "Bearer "+tr.Token)
	return next.ServeHTTP(w, r)
}

// --- Caddyfile ---

func (m *SessionToJwt) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "jwt_url":
				if !d.Args(&m.JwtUrl) {
					return d.ArgErr()
				}
			case "shared_secret":
				if !d.Args(&m.SharedSecret) {
					return d.ArgErr()
				}
			case "cookie_name":
				if !d.Args(&m.CookieName) {
					return d.ArgErr()
				}
			case "cache_ttl_seconds":
				var v string
				if !d.Args(&v) {
					return d.ArgErr()
				}
				ttl, err := time.ParseDuration(v + "s")
				if err != nil {
					return d.Errf("ongeldige cache_ttl_seconds: %v", err)
				}
				m.CacheTtlSeconds = int(ttl.Seconds())
			default:
				return d.Errf("onbekende optie: %s", d.Val())
			}
		}
	}
	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m SessionToJwt
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return &m, err
}

var (
	_ caddy.Provisioner           = (*SessionToJwt)(nil)
	_ caddyhttp.MiddlewareHandler = (*SessionToJwt)(nil)
	_ caddyfile.Unmarshaler       = (*SessionToJwt)(nil)
)
