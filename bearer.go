package session_to_jwt

import (
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// Bearer-pad ("phantom token") voor de native apps.
//
// De app stuurt `Authorization: Bearer <app-token>` (+ optioneel `X-Wit-Org`). Dat
// app-token is ondoorzichtig voor Hasura: de proxy ruilt het bij het token-endpoint
// in voor een JWT en vervangt de Authorization-header daarmee. Anders dan het
// cookie-pad is dit pad fail-CLOSED: zonder verse JWT gaat er niets naar upstream,
// en het app-token zelf bereikt upstream nooit.
//
// LET OP: log nooit tokens, Authorization, cookies of de combinatie org+token.

const (
	errAmbiguousCredentials = "ambiguous_credentials"
	errInvalidSession       = "invalid_session"
	errOrgNotAllowed        = "org_not_allowed"
	errAuthUnavailable      = "auth_unavailable"

	// orgHeader kiest de organisatie waarvoor de app een JWT wil.
	orgHeader = "X-Wit-Org"

	// defaultBearerTimeout begrenst de token-call op het bearer-pad; bij een
	// time-out volgt 503 in plaats van een hangende request.
	defaultBearerTimeout = 10 * time.Second

	// maxTokenResponseBytes begrenst hoeveel van de token-response we inlezen.
	maxTokenResponseBytes = 64 << 10
)

var orgPattern = regexp.MustCompile(`^[0-9]{1,10}$`)

// writeJSONError schrijft een korte JSON-foutbody, bv. {"error":"invalid_session"}.
func writeJSONError(w http.ResponseWriter, status int, code string) error {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, err := w.Write([]byte(`{"error":"` + code + `"}`))
	return err
}

// parseBearer haalt het token uit een `Bearer <x>`-header (scheme case-insensitief).
func parseBearer(h string) (string, bool) {
	const prefix = "bearer "
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	tok := strings.TrimSpace(h[len(prefix):])
	if tok == "" || strings.ContainsAny(tok, " \t") {
		return "", false
	}
	return tok, true
}

// serveBearer handelt een request af dat een Authorization-header heeft maar geen sessie-cookie.
func (m *SessionToJwt) serveBearer(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Precies één Authorization-header, en die moet Bearer zijn. Alles anders
	// (Basic, leeg, meerdere headers) -> 401: een door de client meegestuurde
	// Authorization mag nooit ongewijzigd naar Hasura.
	vals := r.Header.Values("Authorization")
	if len(vals) != 1 {
		return writeJSONError(w, http.StatusUnauthorized, errInvalidSession)
	}
	tok, ok := parseBearer(vals[0])
	if !ok {
		return writeJSONError(w, http.StatusUnauthorized, errInvalidSession)
	}

	// Optionele X-Wit-Org: alleen cijfers (1-10), anders 403 zonder token-call.
	org := ""
	if orgVals := r.Header.Values(orgHeader); len(orgVals) > 0 {
		if len(orgVals) != 1 || !orgPattern.MatchString(orgVals[0]) {
			return writeJSONError(w, http.StatusForbidden, errOrgNotAllowed)
		}
		org = orgVals[0]
	}

	// 1) Cache? (namespace "bearer:<token>:<org>", los van de cookie-keys)
	if cached, ok := m.cache.GetBearer(tok, org); ok {
		r.Header.Set("Authorization", "Bearer "+string(cached))
		return next.ServeHTTP(w, r)
	}

	// 2) Token ophalen: secret + app-token + org, GEEN cookie.
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, m.JwtUrl, nil)
	if err != nil {
		m.logger.Error("bearer: kon token-request niet maken", zap.Error(err))
		return writeJSONError(w, http.StatusServiceUnavailable, errAuthUnavailable)
	}
	req.Header.Set("x-proxy-secret", m.SharedSecret)
	req.Header.Set("Authorization", "Bearer "+tok)
	if org != "" {
		req.Header.Set(orgHeader, org)
	}

	client := m.bearerClient
	if client == nil {
		client = &http.Client{Timeout: defaultBearerTimeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		// Fout bevat alleen URL/netwerkdetails, geen headers.
		m.logger.Error("bearer: token-endpoint onbereikbaar", zap.Error(err))
		return writeJSONError(w, http.StatusServiceUnavailable, errAuthUnavailable)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseBytes))

	switch resp.StatusCode {
	case http.StatusOK:
		// verder hieronder
	case http.StatusUnauthorized:
		return writeJSONError(w, http.StatusUnauthorized, errInvalidSession)
	case http.StatusForbidden:
		var er struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &er) == nil && er.Error == errOrgNotAllowed {
			return writeJSONError(w, http.StatusForbidden, errOrgNotAllowed)
		}
		// Bv. 403 door een fout shared secret: configuratieprobleem, niet de schuld van de app.
		m.logger.Error("bearer: token-endpoint weigerde (403)", zap.Int("status", resp.StatusCode))
		return writeJSONError(w, http.StatusServiceUnavailable, errAuthUnavailable)
	default:
		m.logger.Error("bearer: onverwachte status van token-endpoint", zap.Int("status", resp.StatusCode))
		return writeJSONError(w, http.StatusServiceUnavailable, errAuthUnavailable)
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil || tr.Token == "" {
		m.logger.Error("bearer: ongeldige token-response")
		return writeJSONError(w, http.StatusServiceUnavailable, errAuthUnavailable)
	}

	// 3) Cachen (zelfde TTL-regel als het cookie-pad) en Authorization OVERSCHRIJVEN,
	// zodat het app-token nooit upstream terechtkomt.
	m.cache.SetBearer(tok, org, []byte(tr.Token), m.ttlFor(tr.Exp))
	r.Header.Set("Authorization", "Bearer "+tr.Token)
	return next.ServeHTTP(w, r)
}
