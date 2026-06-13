package session_to_jwt

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func TestServeHTTP_InjectsBearerFromTokenEndpoint(t *testing.T) {
	// Fake token-endpoint: verwacht secret + cookie, geeft een token terug.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-proxy-secret") != "s3cret" {
			w.WriteHeader(403)
			return
		}
		if c, err := r.Cookie("better-auth.session_token"); err != nil || c.Value != "sess123" {
			w.WriteHeader(401)
			return
		}
		w.Write([]byte(`{"token":"jwt-abc","exp":0}`))
	}))
	defer ts.Close()

	m := &SessionToJwt{JwtUrl: ts.URL, SharedSecret: "s3cret", CookieName: "better-auth.session_token", CacheTtlSeconds: 300, logger: zap.NewNop(), cache: NewCache()}

	var seen string
	nextHandler := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		seen = r.Header.Get("Authorization")
		return nil
	})

	req := httptest.NewRequest("POST", "http://x/v1/graphql", nil)
	req.AddCookie(&http.Cookie{Name: "better-auth.session_token", Value: "sess123"})
	if err := m.ServeHTTP(httptest.NewRecorder(), req, nextHandler); err != nil {
		t.Fatal(err)
	}
	if seen != "Bearer jwt-abc" {
		t.Fatalf("verwachtte Bearer jwt-abc, kreeg %q", seen)
	}

	// Tweede request: uit cache (token-endpoint niet opnieuw nodig).
	ts.Close()
	req2 := httptest.NewRequest("POST", "http://x/v1/graphql", nil)
	req2.AddCookie(&http.Cookie{Name: "better-auth.session_token", Value: "sess123"})
	seen = ""
	if err := m.ServeHTTP(httptest.NewRecorder(), req2, nextHandler); err != nil {
		t.Fatal(err)
	}
	if seen != "Bearer jwt-abc" {
		t.Fatalf("cache-hit faalde: kreeg %q", seen)
	}
}

func TestServeHTTP_NoCookiePassesThrough(t *testing.T) {
	m := &SessionToJwt{CookieName: "better-auth.session_token", logger: zap.NewNop(), cache: NewCache()}
	called := false
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { called = true; return nil })
	req := httptest.NewRequest("POST", "http://x/v1/graphql", nil)
	if err := m.ServeHTTP(httptest.NewRecorder(), req, next); err != nil || !called {
		t.Fatal("zonder cookie moet 'ie doorlaten")
	}
}
