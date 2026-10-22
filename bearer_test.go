package session_to_jwt

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// fakeTokenEndpoint simuleert proxy-jwt voor het bearer-pad: controleert secret,
// verwacht géén cookie en géén X-Wit-Org, en geeft per token een JWT terug.
func fakeTokenEndpoint(t *testing.T, hits *int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		if r.Header.Get("x-proxy-secret") != "s3cret" {
			w.WriteHeader(403)
			w.Write([]byte(`Forbidden`))
			return
		}
		if r.Header.Get("Cookie") != "" {
			t.Error("bearer-pad mag geen cookie naar het token-endpoint sturen")
		}
		switch r.Header.Get("Authorization") {
		case "Bearer app-good":
		default:
			w.WriteHeader(401)
			w.Write([]byte(`{"error":"invalid_session"}`))
			return
		}
		if _, ok := r.Header["X-Wit-Org"]; ok {
			t.Error("bearer-pad mag X-Wit-Org niet naar het token-endpoint sturen")
		}
		w.Write([]byte(`{"token":"jwt-app","exp":0}`))
	}))
}

func newBearerModule(url string) *SessionToJwt {
	return &SessionToJwt{JwtUrl: url, SharedSecret: "s3cret", CookieName: "better-auth.session_token", CacheTtlSeconds: 300, logger: zap.NewNop(), cache: NewCache()}
}

// recordingNext onthoudt of upstream is aangeroepen en welke Authorization hij zag.
type recordingNext struct {
	called bool
	auth   []string
}

func (n *recordingNext) handler() caddyhttp.Handler {
	return caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		n.called = true
		n.auth = r.Header.Values("Authorization")
		return nil
	})
}

func bearerReq(token string) *http.Request {
	req := httptest.NewRequest("POST", "http://x/v1/graphql", nil)
	if token != "" {
		req.Header.Set("Authorization", token)
	}
	return req
}

func assertJSONError(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("verwachtte status %d, kreeg %d", status, rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("verwachtte Content-Type application/json, kreeg %q", ct)
	}
	body, _ := io.ReadAll(rec.Body)
	if want := `{"error":"` + code + `"}`; string(body) != want {
		t.Fatalf("verwachtte body %s, kreeg %s", want, body)
	}
}

func TestBearer_ValidTokenGetsJwtAndPhantomNeverForwarded(t *testing.T) {
	var hits int32
	ts := fakeTokenEndpoint(t, &hits)
	defer ts.Close()
	m := newBearerModule(ts.URL)

	n := &recordingNext{}
	rec := httptest.NewRecorder()
	if err := m.ServeHTTP(rec, bearerReq("Bearer app-good"), n.handler()); err != nil {
		t.Fatal(err)
	}
	if !n.called {
		t.Fatal("upstream had aangeroepen moeten worden")
	}
	if len(n.auth) != 1 || n.auth[0] != "Bearer jwt-app" {
		t.Fatalf("upstream moet precies de JWT zien, kreeg %q", n.auth)
	}
	for _, a := range n.auth {
		if strings.Contains(a, "app-good") {
			t.Fatal("phantom token lekte naar upstream")
		}
	}
}

func TestBearer_LowercaseSchemeAccepted(t *testing.T) {
	var hits int32
	ts := fakeTokenEndpoint(t, &hits)
	defer ts.Close()
	m := newBearerModule(ts.URL)
	n := &recordingNext{}
	// Token-endpoint krijgt altijd een genormaliseerde "Bearer <x>".
	if err := m.ServeHTTP(httptest.NewRecorder(), bearerReq("bearer app-good"), n.handler()); err != nil {
		t.Fatal(err)
	}
	if len(n.auth) != 1 || n.auth[0] != "Bearer jwt-app" {
		t.Fatalf("kreeg %q", n.auth)
	}
}

func TestBearer_CachedPerToken(t *testing.T) {
	var hits int32
	ts := fakeTokenEndpoint(t, &hits)
	defer ts.Close()
	m := newBearerModule(ts.URL)

	for i := 0; i < 3; i++ {
		n := &recordingNext{}
		if err := m.ServeHTTP(httptest.NewRecorder(), bearerReq("Bearer app-good"), n.handler()); err != nil {
			t.Fatal(err)
		}
		if n.auth[0] != "Bearer jwt-app" {
			t.Fatalf("kreeg %q", n.auth)
		}
	}
	if hits != 1 {
		t.Fatalf("zelfde token: verwachtte 1 token-call, kreeg %d", hits)
	}

	// Bearer-cache staat los van de cookie-namespace.
	if _, ok := m.cache.Get("app-good"); ok {
		t.Fatal("bearer-token mag niet in de cookie-namespace staan")
	}
}

func TestBearer_CookieAndAuthorizationIsAmbiguous(t *testing.T) {
	var hits int32
	ts := fakeTokenEndpoint(t, &hits)
	defer ts.Close()
	m := newBearerModule(ts.URL)

	n := &recordingNext{}
	req := bearerReq("Bearer app-good")
	req.AddCookie(&http.Cookie{Name: "better-auth.session_token", Value: "sess123"})
	rec := httptest.NewRecorder()
	if err := m.ServeHTTP(rec, req, n.handler()); err != nil {
		t.Fatal(err)
	}
	assertJSONError(t, rec, http.StatusBadRequest, "ambiguous_credentials")
	if n.called || hits != 0 {
		t.Fatalf("niet proxyen en geen token-call: called=%v hits=%d", n.called, hits)
	}
}

func TestBearer_InvalidTokenIs401(t *testing.T) {
	var hits int32
	ts := fakeTokenEndpoint(t, &hits)
	defer ts.Close()
	m := newBearerModule(ts.URL)

	n := &recordingNext{}
	rec := httptest.NewRecorder()
	_ = m.ServeHTTP(rec, bearerReq("Bearer app-bad"), n.handler())
	assertJSONError(t, rec, http.StatusUnauthorized, "invalid_session")
	if n.called {
		t.Fatal("upstream mag niet aangeroepen worden")
	}
	// Negatieve resultaten worden niet gecachet.
	_ = m.ServeHTTP(httptest.NewRecorder(), bearerReq("Bearer app-bad"), n.handler())
	if hits != 2 {
		t.Fatalf("negatief resultaat mag niet gecachet worden, hits=%d", hits)
	}
}

// X-Wit-Org bestaat niet meer: het JWT draagt altijd de thuisorganisatie. Een
// meegestuurde header (geldig of niet) verandert niets en gaat niet naar het
// token-endpoint (fakeTokenEndpoint faalt dan).
func TestBearer_OrgHeaderIgnored(t *testing.T) {
	var hits int32
	ts := fakeTokenEndpoint(t, &hits)
	defer ts.Close()
	m := newBearerModule(ts.URL)

	for _, org := range []string{"42", "7", "abc", ""} {
		n := &recordingNext{}
		rec := httptest.NewRecorder()
		req := bearerReq("Bearer app-good")
		req.Header["X-Wit-Org"] = []string{org}
		if err := m.ServeHTTP(rec, req, n.handler()); err != nil {
			t.Fatal(err)
		}
		if rec.Code != http.StatusOK || !n.called || n.auth[0] != "Bearer jwt-app" {
			t.Fatalf("org %q: status=%d called=%v auth=%q", org, rec.Code, n.called, n.auth)
		}
	}
	if hits != 1 {
		t.Fatalf("één cache-entry per token, ongeacht X-Wit-Org: hits=%d", hits)
	}
}

func TestBearer_EndpointFailuresAre503(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"500": func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) },
		"403-secret": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(403)
			w.Write([]byte(`Forbidden`))
		},
		"403-andere-json": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(403)
			w.Write([]byte(`{"error":"forbidden"}`))
		},
		"400":        func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(400) },
		"bad-json":   func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`nope`)) },
		"lege-token": func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"token":"","exp":0}`)) },
		"time-out": func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(300 * time.Millisecond)
			w.Write([]byte(`{"token":"jwt-te-laat","exp":0}`))
		},
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			ts := httptest.NewServer(h)
			defer ts.Close()
			m := newBearerModule(ts.URL)
			m.bearerClient = &http.Client{Timeout: 50 * time.Millisecond}
			n := &recordingNext{}
			rec := httptest.NewRecorder()
			_ = m.ServeHTTP(rec, bearerReq("Bearer app-good"), n.handler())
			assertJSONError(t, rec, http.StatusServiceUnavailable, "auth_unavailable")
			if n.called {
				t.Fatal("fail-closed: upstream mag niet aangeroepen worden")
			}
		})
	}

	t.Run("onbereikbaar", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		url := ts.URL
		ts.Close()
		m := newBearerModule(url)
		n := &recordingNext{}
		rec := httptest.NewRecorder()
		_ = m.ServeHTTP(rec, bearerReq("Bearer app-good"), n.handler())
		assertJSONError(t, rec, http.StatusServiceUnavailable, "auth_unavailable")
		if n.called {
			t.Fatal("fail-closed: upstream mag niet aangeroepen worden")
		}
	})
}

func TestBearer_NonBearerAuthorizationIs401(t *testing.T) {
	var hits int32
	ts := fakeTokenEndpoint(t, &hits)
	defer ts.Close()
	m := newBearerModule(ts.URL)

	for _, h := range []string{"Basic dXNlcjpwYXNz", "Bearer", "Bearer ", "Bearer a b", "app-good", ""} {
		n := &recordingNext{}
		req := httptest.NewRequest("POST", "http://x/v1/graphql", nil)
		req.Header["Authorization"] = []string{h}
		rec := httptest.NewRecorder()
		_ = m.ServeHTTP(rec, req, n.handler())
		assertJSONError(t, rec, http.StatusUnauthorized, "invalid_session")
		if n.called {
			t.Fatalf("%q: client-Authorization mag nooit doorgaan naar upstream", h)
		}
	}
	// Meerdere Authorization-headers: ook 401.
	req := httptest.NewRequest("POST", "http://x/v1/graphql", nil)
	req.Header["Authorization"] = []string{"Bearer app-good", "Bearer app-good"}
	rec := httptest.NewRecorder()
	_ = m.ServeHTTP(rec, req, (&recordingNext{}).handler())
	assertJSONError(t, rec, http.StatusUnauthorized, "invalid_session")

	if hits != 0 {
		t.Fatalf("token-endpoint mag niet aangeroepen worden, hits=%d", hits)
	}
}

func TestBearer_WebsocketUpgradeStripsAuthorization(t *testing.T) {
	var hits int32
	ts := fakeTokenEndpoint(t, &hits)
	defer ts.Close()
	m := newBearerModule(ts.URL)

	n := &recordingNext{}
	req := bearerReq("Bearer app-good")
	req.Method = "GET"
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	if err := m.ServeHTTP(httptest.NewRecorder(), req, n.handler()); err != nil {
		t.Fatal(err)
	}
	if !n.called {
		t.Fatal("upgrade moet doorgelaten worden")
	}
	if len(n.auth) != 0 {
		t.Fatalf("upgrade mag geen (phantom) Authorization doorsturen, kreeg %q", n.auth)
	}
	if hits != 0 {
		t.Fatal("upgrade mag geen token-call doen")
	}
}

func TestEvict_BearerRemovesToken(t *testing.T) {
	c := SharedCache()
	c.SetBearer("app-tok", []byte("jwt-a"), 300)
	c.SetBearer("app-tok-2", []byte("jwt-ander"), 300) // token met dezelfde prefix
	c.SetBearer("ander", []byte("jwt-d"), 300)
	c.Set("app-tok", []byte("jwt-cookie"), 300) // cookie-namespace met dezelfde waarde

	m := &SessionToJwtEvict{SharedSecret: "s3cret", CookieName: "better-auth.session_token", logger: zap.NewNop()}

	// Zonder secret: 403, niets weg.
	req := httptest.NewRequest("POST", "http://x/internal/auth-evict", nil)
	req.Header.Set("Authorization", "Bearer app-tok")
	rec := httptest.NewRecorder()
	_ = m.ServeHTTP(rec, req, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("zonder secret verwacht 403, kreeg %d", rec.Code)
	}
	if _, ok := c.GetBearer("app-tok"); !ok {
		t.Fatal("403 mag niets verwijderen")
	}

	req = httptest.NewRequest("POST", "http://x/internal/auth-evict", nil)
	req.Header.Set("x-proxy-secret", "s3cret")
	req.Header.Set("Authorization", "Bearer app-tok")
	rec = httptest.NewRecorder()
	_ = m.ServeHTTP(rec, req, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("verwacht 204, kreeg %d", rec.Code)
	}
	if _, ok := c.GetBearer("app-tok"); ok {
		t.Fatal("app-tok had verwijderd moeten zijn")
	}
	if _, ok := c.GetBearer("app-tok-2"); !ok {
		t.Fatal("token met dezelfde prefix mag niet geraakt worden")
	}
	if _, ok := c.GetBearer("ander"); !ok {
		t.Fatal("ander token mag niet geraakt worden")
	}
	if _, ok := c.Get("app-tok"); !ok {
		t.Fatal("cookie-namespace mag niet geraakt worden door bearer-evict")
	}
}
