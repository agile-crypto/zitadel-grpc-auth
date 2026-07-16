package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/agile-crypto/zitadel-grpc-auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeZitadel is a minimal fake of Zitadel's /oauth/v2/introspect endpoint.
// It validates HTTP Basic credentials and returns canned responses keyed by
// the submitted token.
type fakeZitadel struct {
	expectedID, expectedSecret string
	responses                  map[string]map[string]any // token → introspection JSON
	calls                      atomic.Int32
}

func (f *fakeZitadel) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 "http://" + r.Host,
				"token_endpoint":         "http://" + r.Host + "/oauth/v2/token",
				"introspection_endpoint": "http://" + r.Host + "/oauth/v2/introspect",
			})
			return
		}
		if r.URL.Path != "/oauth/v2/introspect" {
			http.NotFound(w, r)
			return
		}
		// Validate basic auth
		hdr := r.Header.Get("Authorization")
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte(f.expectedID+":"+f.expectedSecret))
		if hdr != want {
			http.Error(w, "bad credentials", http.StatusUnauthorized)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		tok := r.PostForm.Get("token")
		w.Header().Set("Content-Type", "application/json")
		body, ok := f.responses[tok]
		if !ok {
			body = map[string]any{"active": false}
		}
		_ = json.NewEncoder(w).Encode(body)
	})
}

// TestServer_EndToEnd_WithRealIntrospector wires the real
// httpIntrospector against a fake Zitadel and asserts both the success and
// failure paths through the full pipeline.
func TestServer_EndToEnd_WithRealIntrospector(t *testing.T) {
	fz := &fakeZitadel{
		expectedID:     "intro-id",
		expectedSecret: "intro-secret",
		responses: map[string]map[string]any{
			"alice-tok": {
				"active":                 true,
				"sub":                    "alice",
				"exp":                    float64(time.Now().Add(time.Hour).Unix()),
				"urn:citius:permissions": []any{"citius:read"},
			},
			"bob-tok": {
				"active": true,
				"sub":    "bob",
				"exp":    float64(time.Now().Add(time.Hour).Unix()),
				// no permissions
			},
		},
	}
	zsrv := httptest.NewServer(fz.handler())
	defer zsrv.Close()

	requireRead := func(_ context.Context, _ string, c *auth.Claims) error {
		if !c.HasStringInSlice("urn:citius:permissions", "citius:read") {
			return auth.Forbidden("missing citius:read")
		}
		return nil
	}

	srvOpts, closer, err := New(Config{
		RequireAuth:               true,
		Issuer:                    zsrv.URL,
		IntrospectionClientID:     "intro-id",
		IntrospectionClientSecret: "intro-secret",
		Insecure:                  true,
		CacheTTL:                  30 * time.Second,
		CacheMaxEntries:           10,
		Policies: map[string][]auth.PolicyFunc{
			"/grpc.health.v1.Health/Check": {requireRead},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer closer.Close()

	addr, _, stop := startServer(t, srvOpts)
	defer stop()
	conn := dial(t, addr)
	defer conn.Close()

	// alice — has read → OK
	if err := callCheckWithToken(t, conn, "alice-tok"); err != nil {
		t.Fatalf("alice: expected OK, got %v", err)
	}
	// alice repeated → cache hit, no extra introspection
	beforeCalls := fz.calls.Load()
	if err := callCheckWithToken(t, conn, "alice-tok"); err != nil {
		t.Fatal(err)
	}
	if fz.calls.Load() != beforeCalls {
		t.Fatal("expected cache to absorb second call")
	}

	// bob — active but missing permission → PermissionDenied
	err = callCheckWithToken(t, conn, "bob-tok")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("bob: expected PermissionDenied, got %v", err)
	}

	// unknown — fake returns active=false → Unauthenticated
	err = callCheckWithToken(t, conn, "rando-tok")
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("rando: expected Unauthenticated, got %v", err)
	}
	if !strings.Contains(status.Convert(err).Message(), "not active") {
		t.Logf("note: error message was %q", err.Error())
	}
}
