package session_to_jwt

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"
)

func TestEvict_DeletesCachedToken(t *testing.T) {
	SharedCache().Set("sess123", []byte("jwt-abc"), 300)
	if _, ok := SharedCache().Get("sess123"); !ok {
		t.Fatal("setup: verwachtte cache-hit")
	}

	m := &SessionToJwtEvict{SharedSecret: "s3cret", CookieName: "better-auth.session_token", logger: zap.NewNop()}

	// fout/ontbrekend secret -> 403, niets verwijderd
	req := httptest.NewRequest("POST", "http://x/internal/auth-evict", nil)
	req.AddCookie(&http.Cookie{Name: "better-auth.session_token", Value: "sess123"})
	rec := httptest.NewRecorder()
	_ = m.ServeHTTP(rec, req, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("zonder secret verwacht 403, kreeg %d", rec.Code)
	}
	if _, ok := SharedCache().Get("sess123"); !ok {
		t.Fatal("403 mag niets verwijderen")
	}

	// juist secret -> 204, entry weg
	req2 := httptest.NewRequest("POST", "http://x/internal/auth-evict", nil)
	req2.Header.Set("x-proxy-secret", "s3cret")
	req2.AddCookie(&http.Cookie{Name: "better-auth.session_token", Value: "sess123"})
	rec2 := httptest.NewRecorder()
	_ = m.ServeHTTP(rec2, req2, nil)
	if rec2.Code != http.StatusNoContent {
		t.Fatalf("met secret verwacht 204, kreeg %d", rec2.Code)
	}
	if _, ok := SharedCache().Get("sess123"); ok {
		t.Fatal("entry had verwijderd moeten zijn")
	}
}
