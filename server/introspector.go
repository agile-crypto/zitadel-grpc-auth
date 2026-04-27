package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	auth "github.ibm.com/citius/zitadel-grpc-auth"
)

// httpIntrospector implements [Introspector] by POSTing to the OAuth2 token
// introspection endpoint at Issuer + "/oauth/v2/introspect" using HTTP
// Basic auth with the API application's client_id and client_secret.
//
// The implementation is intentionally kept as an explicit opt-in fallback.
// It remains useful when callers want full control over the http.Client or
// want to avoid the SDK-backed default implementation.
type httpIntrospector struct {
	endpoint     string
	clientID     string
	clientSecret string
	http         *http.Client
}

// defaultHTTPTimeout bounds a single introspection round-trip when the
// caller does not supply an http.Client of their own. It is intentionally
// well below typical gRPC deadlines so that a stalled upstream cannot
// pin an interceptor goroutine indefinitely.
const defaultHTTPTimeout = 10 * time.Second

// NewHTTPIntrospector returns the default introspector. The endpoint is
// derived as issuer + "/oauth/v2/introspect". If httpClient is nil, an
// http.Client with a bounded timeout is constructed; http.DefaultClient is
// deliberately NOT used because it has no timeout and can wedge the
// interceptor on a stalled upstream.
//
// This constructor is exported so callers can build the introspector
// directly (e.g. to wrap it with metrics or logging) and pass it back
// through [Config.Introspector].
func NewHTTPIntrospector(issuer, clientID, clientSecret string, httpClient *http.Client) Introspector {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultHTTPTimeout}
	}
	return &httpIntrospector{
		endpoint:     strings.TrimRight(issuer, "/") + "/oauth/v2/introspect",
		clientID:     clientID,
		clientSecret: clientSecret,
		http:         httpClient,
	}
}

func (h *httpIntrospector) Introspect(ctx context.Context, token string) (*auth.Claims, time.Time, error) {
	form := url.Values{"token": {token}, "token_type_hint": {"access_token"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("introspect: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(h.clientID, h.clientSecret)

	resp, err := h.http.Do(req)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("introspect: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB cap
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("introspect: read body: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		return nil, time.Time{}, fmt.Errorf("introspect: HTTP %d: %s", resp.StatusCode, truncate(string(body), 256))
	}

	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, time.Time{}, fmt.Errorf("introspect: decode JSON: %w", err)
	}

	claims := auth.NewClaims(raw)
	if !claims.Active() {
		// Wrap the sentinel so the interceptor can map this to
		// codes.Unauthenticated without confusing it with a real I/O
		// error.
		return claims, time.Time{}, auth.Unauthenticated("token not active")
	}
	return claims, claims.Expiration(), nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
