package admin

import (
	"errors"
	"strings"
	"testing"

	userV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
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

func TestNewHumanCreateRequest(t *testing.T) {
	in := HumanOnboardInput{
		Username:               " producer ",
		GivenName:              " Demo ",
		FamilyName:             " Producer ",
		Email:                  "producer@example.test",
		InitialPassword:        "initial-password",
		PasswordChangeRequired: true,
		EmailVerified:          true,
	}

	req := newHumanCreateRequest("org-1", in)
	human := req.GetHuman()
	if req.GetOrganizationId() != "org-1" || req.GetUsername() != "producer" {
		t.Fatalf("unexpected identity: org=%q username=%q", req.GetOrganizationId(), req.GetUsername())
	}
	if human == nil {
		t.Fatal("human configuration missing")
	}
	if human.GetProfile().GetGivenName() != "Demo" || human.GetProfile().GetFamilyName() != "Producer" || human.GetProfile().GetDisplayName() != "Demo Producer" {
		t.Fatalf("unexpected profile: %+v", human.GetProfile())
	}
	if human.GetEmail().GetEmail() != in.Email || !human.GetEmail().GetIsVerified() {
		t.Fatalf("unexpected email: %+v", human.GetEmail())
	}
	if human.GetPassword().GetPassword() != in.InitialPassword || !human.GetPassword().GetChangeRequired() {
		t.Fatal("unexpected initial password configuration")
	}
	if req.GetMachine() != nil {
		t.Fatal("machine configuration must not be set")
	}
}

func TestNewHumanCreateRequestLeavesEmailVerificationPending(t *testing.T) {
	req := newHumanCreateRequest("org-1", HumanOnboardInput{
		Username:        "consumer",
		GivenName:       "Demo",
		FamilyName:      "Consumer",
		Email:           "consumer@example.test",
		InitialPassword: "initial-password",
	})
	if req.GetHuman().GetEmail().GetVerification() != nil {
		t.Fatal("email verification must use Zitadel's default flow when EmailVerified is false")
	}
}

func TestRequireHumanUser(t *testing.T) {
	human := &userV2.User{
		UserId:   "human-1",
		Username: "producer",
		Type:     &userV2.User_Human{Human: &userV2.HumanUser{}},
	}
	machine := &userV2.User{
		UserId:   "machine-1",
		Username: "worker",
		Type:     &userV2.User_Machine{Machine: &userV2.MachineUser{}},
	}

	got, err := requireHumanUser(human, "producer")
	if err != nil || got != human {
		t.Fatalf("requireHumanUser human = (%v, %v), want (%v, nil)", got, err, human)
	}
	got, err = requireHumanUser(nil, "missing")
	if err != nil || got != nil {
		t.Fatalf("requireHumanUser missing = (%v, %v), want (nil, nil)", got, err)
	}
	got, err = requireHumanUser(machine, "worker")
	if got != nil || !errors.Is(err, ErrUserTypeMismatch) {
		t.Fatalf("requireHumanUser machine = (%v, %v), want (nil, ErrUserTypeMismatch)", got, err)
	}
}

func TestHumanLoginName(t *testing.T) {
	user := &userV2.User{Username: "producer", PreferredLoginName: "producer@example.test"}
	if got := humanLoginName(user); got != "producer@example.test" {
		t.Fatalf("humanLoginName = %q, want preferred login name", got)
	}
	user.PreferredLoginName = ""
	if got := humanLoginName(user); got != "producer" {
		t.Fatalf("humanLoginName = %q, want username fallback", got)
	}
}

func TestValidateResetHumanPasswordInput(t *testing.T) {
	tests := []struct {
		name    string
		input   ResetHumanPasswordInput
		wantErr string
	}{
		{
			name:  "valid",
			input: ResetHumanPasswordInput{Username: "producer", NewPassword: "new-password"},
		},
		{
			name:    "missing username",
			input:   ResetHumanPasswordInput{Username: " ", NewPassword: "new-password"},
			wantErr: "Username is required",
		},
		{
			name:    "missing password",
			input:   ResetHumanPasswordInput{Username: "producer"},
			wantErr: "NewPassword is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateResetHumanPasswordInput(tt.input)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validateResetHumanPasswordInput: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validateResetHumanPasswordInput error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestNewSetPasswordRequest(t *testing.T) {
	in := ResetHumanPasswordInput{
		Username:               "producer",
		NewPassword:            "new-password",
		PasswordChangeRequired: true,
	}
	req := newSetPasswordRequest("human-1", in)
	if req.GetUserId() != "human-1" {
		t.Fatalf("user ID = %q, want human-1", req.GetUserId())
	}
	if req.GetNewPassword().GetPassword() != in.NewPassword || !req.GetNewPassword().GetChangeRequired() {
		t.Fatal("unexpected new password configuration")
	}
	if req.GetVerification() != nil {
		t.Fatal("administrator reset must not provide current-password or verification-code credentials")
	}
}
