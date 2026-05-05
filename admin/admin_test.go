package admin

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRenderActionScript(t *testing.T) {
	script, err := RenderActionScript("urn:citius")
	if err != nil {
		t.Fatalf("RenderActionScript: %v", err)
	}
	for _, fragment := range []string{
		"function injectUrnCitiusClaims",
		"'urn:citius:permissions'",
		"'urn:citius:key_access'",
		"'urn:citius:allowed_policy_patterns'",
	} {
		if !strings.Contains(script, fragment) {
			t.Fatalf("script missing %q", fragment)
		}
	}
}

func TestMarshalKeyAccess(t *testing.T) {
	data, err := marshalKeyAccess(KeyAccess{
		AllowedKeyPatterns: []string{"payments-*"},
		DenyKeyPatterns:    []string{"payments-prod-*"},
	})
	if err != nil {
		t.Fatalf("marshalKeyAccess: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if _, ok := decoded["allowed_key_patterns"]; !ok {
		t.Fatal("allowed_key_patterns missing")
	}
	if _, ok := decoded["deny_key_patterns"]; !ok {
		t.Fatal("deny_key_patterns missing")
	}
}

func TestValidatePatterns(t *testing.T) {
	if err := validatePatterns([]string{"payments-*"}, []string{"broken["}); err == nil {
		t.Fatal("expected invalid pattern error for broken bracket")
	}
	if err := validatePatterns([]string{""}); err == nil {
		t.Fatal("expected invalid pattern error for empty")
	}
	if err := validatePatterns([]string{"abc def"}); err == nil {
		t.Fatal("expected invalid pattern error for embedded space")
	}
	if err := validatePatterns([]string{"abc\nxyz"}); err == nil {
		t.Fatal("expected invalid pattern error for newline")
	}
	if err := validatePatterns([]string{"payments-*", "billing-prod-*", "exact:key"}); err != nil {
		t.Fatalf("expected valid patterns to pass, got %v", err)
	}
}

func TestValidatePermission(t *testing.T) {
	for _, ok := range []string{"greeter:admin", "key.read", "billing_v2", "abc-123"} {
		if err := validatePermission(ok); err != nil {
			t.Fatalf("expected %q to be valid, got %v", ok, err)
		}
	}
	for _, bad := range []string{"", "has space", "quote\"", "newline\n", "wild*card"} {
		if err := validatePermission(bad); err == nil {
			t.Fatalf("expected %q to be rejected", bad)
		}
	}
}