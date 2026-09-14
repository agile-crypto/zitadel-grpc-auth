package admin

import (
	"fmt"
	"net/mail"
	"strings"
)

func validateHumanOnboardInput(in HumanOnboardInput) error {
	required := []struct {
		name  string
		value string
	}{
		{name: "Username", value: in.Username},
		{name: "GivenName", value: in.GivenName},
		{name: "FamilyName", value: in.FamilyName},
		{name: "Email", value: in.Email},
	}
	for _, field := range required {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("admin.OnboardHuman: %s is required", field.name)
		}
	}

	address, err := mail.ParseAddress(in.Email)
	if err != nil || address.Address != in.Email {
		return fmt.Errorf("admin.OnboardHuman: Email must be a valid address")
	}
	if in.InitialPassword == "" {
		return fmt.Errorf("admin.OnboardHuman: InitialPassword is required")
	}
	for _, permission := range in.Permissions {
		if err := validatePermission(strings.TrimSpace(permission)); err != nil {
			return fmt.Errorf("admin.OnboardHuman: %w", err)
		}
	}
	if err := validatePatterns(
		in.KeyAccess.AllowedKeyPatterns,
		in.KeyAccess.DenyKeyPatterns,
		in.PolicyAccess.AllowedPolicyPatterns,
		in.PolicyAccess.DenyPolicyPatterns,
	); err != nil {
		return fmt.Errorf("admin.OnboardHuman: %w", err)
	}
	return nil
}
