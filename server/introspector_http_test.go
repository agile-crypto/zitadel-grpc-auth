package server

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPIntrospector_Direct(t *testing.T) {
	fz := &fakeZitadel{
		expectedID:     "intro-id",
		expectedSecret: "intro-secret",
		responses: map[string]map[string]any{
			"alice-tok": {
				"active": true,
				"sub":    "alice",
				"exp":    float64(time.Now().Add(time.Hour).Unix()),
			},
		},
	}
	server := httptest.NewServer(fz.handler())
	defer server.Close()

	intr := NewHTTPIntrospector(server.URL, "intro-id", "intro-secret", nil)
	claims, expiry, err := intr.Introspect(context.Background(), "alice-tok")
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if claims.Subject() != "alice" {
		t.Fatalf("unexpected subject %q", claims.Subject())
	}
	if expiry.IsZero() {
		t.Fatal("expected non-zero expiry")
	}
}
