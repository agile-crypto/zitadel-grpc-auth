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
		t.Fatal("expected invalid pattern error")
	}
}