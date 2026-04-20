package auth

import (
	"errors"
	"testing"
	"time"
)

func TestClaims_NilSafe(t *testing.T) {
	var c *Claims
	if c.Subject() != "" || c.Active() || c.String("anything") != "" {
		t.Fatal("nil Claims accessors must return zero values")
	}
	if c.StringSlice("x") != nil || c.HasStringInSlice("x", "y") {
		t.Fatal("nil Claims slice accessors must return zero values")
	}
	if !c.Expiration().IsZero() {
		t.Fatal("nil Claims Expiration must be zero")
	}
}

func TestClaims_Accessors(t *testing.T) {
	c := NewClaims(map[string]any{
		"active":                  true,
		"sub":                     "alice",
		"username":                "alice@example.com",
		"iss":                     "http://localhost:8080",
		"exp":                     float64(time.Now().Add(time.Hour).Unix()),
		"urn:citius:permissions": []any{"citius:encrypt", "citius:decrypt"},
		"single_string_as_list":   "lonely",
		"native_string_slice":     []string{"a", "b"},
		"nested":                  map[string]any{"k": "v"},
	})

	if !c.Active() || c.Subject() != "alice" || c.Username() != "alice@example.com" {
		t.Fatalf("standard claims wrong: %+v", c.Raw())
	}
	if c.Expiration().IsZero() {
		t.Fatal("Expiration should decode float64 unix")
	}
	got := c.StringSlice("urn:citius:permissions")
	if len(got) != 2 || got[0] != "citius:encrypt" {
		t.Fatalf("StringSlice []any decode failed: %v", got)
	}
	if !c.HasStringInSlice("urn:citius:permissions", "citius:decrypt") {
		t.Fatal("HasStringInSlice should find existing entry")
	}
	if c.HasStringInSlice("urn:citius:permissions", "citius:nope") {
		t.Fatal("HasStringInSlice should not find missing entry")
	}
	if got := c.StringSlice("single_string_as_list"); len(got) != 1 || got[0] != "lonely" {
		t.Fatalf("string-as-slice fallback failed: %v", got)
	}
	if got := c.StringSlice("native_string_slice"); len(got) != 2 {
		t.Fatalf("native []string passthrough failed: %v", got)
	}
	if c.Map("nested")["k"].(string) != "v" {
		t.Fatal("Map accessor failed")
	}
	if c.StringSlice("missing") != nil {
		t.Fatal("missing key should be nil slice")
	}
}

func TestErrors_Sentinels(t *testing.T) {
	err := Forbidden("nope %d", 1)
	if !IsForbidden(err) {
		t.Fatal("Forbidden should wrap ErrForbidden")
	}
	if IsUnauthenticated(err) {
		t.Fatal("Forbidden must not be IsUnauthenticated")
	}
	if !errors.Is(err, ErrForbidden) {
		t.Fatal("errors.Is must work with ErrForbidden")
	}

	err2 := Unauthenticated("missing")
	if !IsUnauthenticated(err2) || IsForbidden(err2) {
		t.Fatal("Unauthenticated wraps wrong sentinel")
	}
}
