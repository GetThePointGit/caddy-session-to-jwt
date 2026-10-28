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

func TestServeHTTP_WebsocketUpgradeGetsNoJwt(t *testing.T) {
	// Token-endpoint dat zou falen als het toch werd aangeroepen: de upgrade
	// hoort er niet langs te komen (waterworks#287).
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("token-endpoint aangeroepen voor een websocket-upgrade")
		w.Write([]byte(`{"token":"jwt-abc","exp":0}`))
	}))
	defer ts.Close()

	m := &SessionToJwt{JwtUrl: ts.URL, SharedSecret: "s3cret", CookieName: "better-auth.session_token", CacheTtlSeconds: 300, logger: zap.NewNop(), cache: NewCache()}

	called := false
	var seen string
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		seen = r.Header.Get("Authorization")
		return nil
	})

	req := httptest.NewRequest("GET", "http://x/v1/graphql", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.AddCookie(&http.Cookie{Name: "better-auth.session_token", Value: "sess123"})
	if err := m.ServeHTTP(httptest.NewRecorder(), req, next); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("upgrade moet doorgelaten worden")
	}
	if seen != "" {
		t.Fatalf("upgrade mag geen Authorization-header krijgen, kreeg %q", seen)
	}
}

func TestServeHTTP_WebsocketUpgradeIsCaseInsensitive(t *testing.T) {
	// Werkend token-endpoint: zonder de upgrade-check zou hier een Authorization
	// -header uit rollen, dus de assertie hieronder is niet vacuum.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"token":"jwt-abc","exp":0}`))
	}))
	defer ts.Close()

	m := &SessionToJwt{JwtUrl: ts.URL, SharedSecret: "s3cret", CookieName: "better-auth.session_token", CacheTtlSeconds: 300, logger: zap.NewNop(), cache: NewCache()}
	var seen string
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		seen = r.Header.Get("Authorization")
		return nil
	})
	req := httptest.NewRequest("GET", "http://x/v1/graphql", nil)
	req.Header.Set("Upgrade", "WebSocket")
	req.AddCookie(&http.Cookie{Name: "better-auth.session_token", Value: "sess123"})
	if err := m.ServeHTTP(httptest.NewRecorder(), req, next); err != nil {
		t.Fatal(err)
	}
	if seen != "" {
		t.Fatalf("Upgrade-waarde hoort case-insensitief te matchen, kreeg %q", seen)
	}
}

func TestServeHTTP_CookiePathStaysFailOpen(t *testing.T) {
	// Cookie-pad is ongewijzigd fail-open: token-endpoint stuk -> toch doorlaten, zonder JWT.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer ts.Close()
	m := &SessionToJwt{JwtUrl: ts.URL, SharedSecret: "s3cret", CookieName: "better-auth.session_token", CacheTtlSeconds: 300, logger: zap.NewNop(), cache: NewCache()}
	called := false
	var seen string
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		seen = r.Header.Get("Authorization")
		return nil
	})
	req := httptest.NewRequest("POST", "http://x/v1/graphql", nil)
	req.AddCookie(&http.Cookie{Name: "better-auth.session_token", Value: "sess123"})
	rec := httptest.NewRecorder()
	if err := m.ServeHTTP(rec, req, next); err != nil {
		t.Fatal(err)
	}
	if !called || seen != "" || rec.Code != 200 {
		t.Fatalf("fail-open verwacht: called=%v auth=%q code=%d", called, seen, rec.Code)
	}
}
