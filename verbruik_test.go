package session_to_jwt

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"go.uber.org/zap"
)

// testJWT maakt een (ongetekend) token met de gegeven payload.
func testJWT(payload string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"RS256"}`)) + "." + enc([]byte(payload)) + ".handtekening"
}

// waarnemingen geeft per venster-label het aantal waarnemingen en hun som.
func waarnemingen(t *testing.T, v *Verbruik) map[string][2]float64 {
	t.Helper()
	reg := prometheus.NewRegistry()
	if err := v.Registreer(reg); err != nil {
		t.Fatal(err)
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	uit := map[string][2]float64{}
	for _, f := range families {
		for _, m := range f.GetMetric() {
			uit[label(m, "venster")] = [2]float64{float64(m.GetHistogram().GetSampleCount()), m.GetHistogram().GetSampleSum()}
		}
	}
	return uit
}

func label(m *dto.Metric, naam string) string {
	for _, l := range m.GetLabel() {
		if l.GetName() == naam {
			return l.GetValue()
		}
	}
	return ""
}

func TestGebruikerUitJWT(t *testing.T) {
	gevallen := []struct{ naam, token, wil string }{
		{"sub als string", testJWT(`{"sub":"42"}`), "42"},
		{"sub als getal", testJWT(`{"sub":42}`), "42"},
		{"hasura-claim als terugval", testJWT(`{"https://hasura.io/jwt/claims":{"x-hasura-user-id":7}}`), "7"},
		{"sub wint van de hasura-claim", testJWT(`{"sub":"1","https://hasura.io/jwt/claims":{"x-hasura-user-id":"2"}}`), "1"},
		{"geen gebruiker", testJWT(`{"iss":"x"}`), ""},
		{"geen JWT", "jwt-abc", ""},
		{"kapotte payload", "a.!!!.c", ""},
		{"geen JSON", "a." + base64.RawURLEncoding.EncodeToString([]byte("nee")) + ".c", ""},
	}
	for _, g := range gevallen {
		if kreeg := gebruikerUitJWT([]byte(g.token)); kreeg != g.wil {
			t.Errorf("%s: kreeg %q, wil %q", g.naam, kreeg, g.wil)
		}
	}
}

func TestVerbruik_EenWaarnemingPerGebruikerPerVenster(t *testing.T) {
	v := NewVerbruik()
	a, b := []byte(testJWT(`{"sub":"a"}`)), []byte(testJWT(`{"sub":"b"}`))
	for i := 0; i < 5; i++ {
		v.Tel(a)
	}
	v.Tel(b)
	v.Tel([]byte("geen-jwt")) // telt niet mee
	v.Tik()

	w := waarnemingen(t, v)
	if w[labelKort] != [2]float64{2, 6} {
		t.Fatalf("kort venster: kreeg (aantal, som) %v, wil [2 6]", w[labelKort])
	}
	if w[labelLang][0] != 0 {
		t.Fatalf("lang venster mag nog niet gesloten zijn: %v", w[labelLang])
	}

	// Na tikkenPerLang tikken sluit het lange venster: a deed 5+3, b deed 1.
	for i := 0; i < 3; i++ {
		v.Tel(a)
	}
	for i := 1; i < tikkenPerLang; i++ {
		v.Tik()
	}
	w = waarnemingen(t, v)
	if w[labelLang] != [2]float64{2, 9} {
		t.Fatalf("lang venster: kreeg %v, wil [2 9]", w[labelLang])
	}
	// Kort: eerste tik 2 waarnemingen (5 en 1), tweede tik 1 (3); lege vensters geven niets.
	if w[labelKort] != [2]float64{3, 9} {
		t.Fatalf("kort venster: kreeg %v, wil [3 9]", w[labelKort])
	}
}

func TestVerbruik_RegistreerTweeKeerIsGeenFout(t *testing.T) {
	v := NewVerbruik()
	reg := prometheus.NewRegistry()
	if err := v.Registreer(reg); err != nil {
		t.Fatal(err)
	}
	if err := v.Registreer(reg); err != nil {
		t.Fatalf("tweede registratie: %v", err)
	}
	if err := v.Registreer(nil); err != nil {
		t.Fatalf("nil-registry: %v", err)
	}
}

func TestServeHTTP_TeltCookieEnBearerVerzoeken(t *testing.T) {
	token := testJWT(`{"sub":"9"}`)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"token":"` + token + `","exp":0}`))
	}))
	defer ts.Close()

	v := NewVerbruik()
	m := &SessionToJwt{JwtUrl: ts.URL, SharedSecret: "s", CookieName: "better-auth.session_token", CacheTtlSeconds: 300, logger: zap.NewNop(), cache: NewCache(), verbruik: v}
	next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil })

	doe := func(zet func(*http.Request)) {
		t.Helper()
		req := httptest.NewRequest("POST", "http://x/v1/graphql", nil)
		zet(req)
		if err := m.ServeHTTP(httptest.NewRecorder(), req, next); err != nil {
			t.Fatal(err)
		}
	}
	cookie := func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: "better-auth.session_token", Value: "sess"})
	}
	doe(cookie) // vers opgehaald
	doe(cookie) // uit de cache
	doe(func(r *http.Request) { r.Header.Set("Authorization", "Bearer app-token") })
	doe(func(r *http.Request) { r.Header.Set("Authorization", "Bearer app-token") })
	doe(func(*http.Request) {}) // zonder sessie: telt niet
	doe(func(r *http.Request) { // websocket-upgrade: telt niet
		cookie(r)
		r.Header.Set("Upgrade", "websocket")
	})
	v.Tik()

	if w := waarnemingen(t, v); w[labelKort] != [2]float64{1, 4} {
		t.Fatalf("kreeg (aantal, som) %v, wil [1 4]: één gebruiker, vier verzoeken", w[labelKort])
	}
}
