package admin

import (
	"strings"
	"testing"
)

func TestValidateHumanOnboardInput(t *testing.T) {
	valid := HumanOnboardInput{
		Username:        "producer",
		GivenName:       "Demo",
		FamilyName:      "Producer",
		DisplayName:     "Demo Producer",
		Email:           "producer@example.test",
		InitialPassword: "initial-password",
		Permissions:     []string{"key:create", "crypto:encrypt"},
		KeyAccess: KeyAccess{
			AllowedKeyPatterns: []string{"demo-*"},
			DenyKeyPatterns:    []string{"demo-restricted-*"},
		},
		PolicyAccess: PolicyAccess{
			AllowedPolicyPatterns: []string{"demo-*"},
		},
	}

	tests := []struct {
		name    string
		mutate  func(*HumanOnboardInput)
		wantErr string
	}{
		{name: "valid"},
		{name: "missing username", mutate: func(in *HumanOnboardInput) { in.Username = " " }, wantErr: "Username is required"},
		{name: "missing given name", mutate: func(in *HumanOnboardInput) { in.GivenName = "" }, wantErr: "GivenName is required"},
		{name: "missing family name", mutate: func(in *HumanOnboardInput) { in.FamilyName = "\t" }, wantErr: "FamilyName is required"},
		{name: "missing email", mutate: func(in *HumanOnboardInput) { in.Email = "" }, wantErr: "Email is required"},
		{name: "invalid email", mutate: func(in *HumanOnboardInput) { in.Email = "Demo <producer@example.test>" }, wantErr: "Email must be a valid address"},
		{name: "missing password", mutate: func(in *HumanOnboardInput) { in.InitialPassword = "" }, wantErr: "InitialPassword is required"},
		{name: "invalid permission", mutate: func(in *HumanOnboardInput) { in.Permissions = []string{"crypto:*"} }, wantErr: "permission"},
		{name: "invalid key pattern", mutate: func(in *HumanOnboardInput) { in.KeyAccess.AllowedKeyPatterns = []string{"demo key"} }, wantErr: "invalid glob pattern"},
		{name: "invalid policy pattern", mutate: func(in *HumanOnboardInput) { in.PolicyAccess.DenyPolicyPatterns = []string{"demo["} }, wantErr: "invalid glob pattern"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := valid
			in.Permissions = append([]string(nil), valid.Permissions...)
			in.KeyAccess.AllowedKeyPatterns = append([]string(nil), valid.KeyAccess.AllowedKeyPatterns...)
			in.KeyAccess.DenyKeyPatterns = append([]string(nil), valid.KeyAccess.DenyKeyPatterns...)
			in.PolicyAccess.AllowedPolicyPatterns = append([]string(nil), valid.PolicyAccess.AllowedPolicyPatterns...)
			if tt.mutate != nil {
				tt.mutate(&in)
			}

			err := validateHumanOnboardInput(in)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validateHumanOnboardInput: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validateHumanOnboardInput error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}
