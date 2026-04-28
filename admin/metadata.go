package admin

import "encoding/json"

type keyAccessMetadata struct {
	AllowedKeyPatterns []string `json:"allowed_key_patterns,omitempty"`
	DenyKeyPatterns    []string `json:"deny_key_patterns,omitempty"`
}

type policyAccessMetadata struct {
	AllowedPolicyPatterns []string `json:"allowed_policy_patterns,omitempty"`
	DenyPolicyPatterns    []string `json:"deny_policy_patterns,omitempty"`
}

func keyAccessMetadataKey(namespace string) string {
	return normalizeNamespace(namespace, "") + ":key_access"
}

func policyAccessMetadataKey(namespace string) string {
	return normalizeNamespace(namespace, "") + ":policy_access"
}

func marshalKeyAccess(access KeyAccess) ([]byte, error) {
	return json.Marshal(keyAccessMetadata{
		AllowedKeyPatterns: append([]string(nil), access.AllowedKeyPatterns...),
		DenyKeyPatterns:    append([]string(nil), access.DenyKeyPatterns...),
	})
}

func marshalPolicyAccess(access PolicyAccess) ([]byte, error) {
	return json.Marshal(policyAccessMetadata{
		AllowedPolicyPatterns: append([]string(nil), access.AllowedPolicyPatterns...),
		DenyPolicyPatterns:    append([]string(nil), access.DenyPolicyPatterns...),
	})
}

func hasKeyAccess(access KeyAccess) bool {
	return len(access.AllowedKeyPatterns) > 0 || len(access.DenyKeyPatterns) > 0
}

func hasPolicyAccess(access PolicyAccess) bool {
	return len(access.AllowedPolicyPatterns) > 0 || len(access.DenyPolicyPatterns) > 0
}
