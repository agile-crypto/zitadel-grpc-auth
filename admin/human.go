package admin

import (
	"context"
	"fmt"
	"net/mail"
	"strings"

	userV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
)

func (c *Client) OnboardHuman(ctx context.Context, in HumanOnboardInput) (*HumanOnboardResult, error) {
	if err := validateHumanOnboardInput(in); err != nil {
		return nil, err
	}

	project, err := c.resolveProject(ctx)
	if err != nil {
		return nil, fmt.Errorf("admin.OnboardHuman: resolve project: %w", err)
	}
	orgID, err := c.resolveOrgID(ctx)
	if err != nil {
		return nil, fmt.Errorf("admin.OnboardHuman: resolve org: %w", err)
	}

	user, created, err := c.ensureHumanUser(ctx, orgID, in)
	if err != nil {
		return nil, fmt.Errorf("admin.OnboardHuman: ensure human user: %w", err)
	}
	if err := c.reconcileAuthorizations(ctx, orgID, project.GetProjectId(), user.GetUserId(), in.Permissions); err != nil {
		return nil, fmt.Errorf("admin.OnboardHuman: reconcile authorizations: %w", err)
	}
	if err := c.reconcileMetadata(ctx, user.GetUserId(), in.KeyAccess, in.PolicyAccess); err != nil {
		return nil, fmt.Errorf("admin.OnboardHuman: reconcile metadata: %w", err)
	}

	result := &HumanOnboardResult{
		UserID:    user.GetUserId(),
		LoginName: humanLoginName(user),
		Created:   created,
	}
	c.logger.Info("onboarded Zitadel human user", "username", strings.TrimSpace(in.Username), "user_id", result.UserID, "project_id", project.GetProjectId(), "created", created)
	return result, nil
}

func (c *Client) ResetHumanPassword(ctx context.Context, in ResetHumanPasswordInput) error {
	if err := validateResetHumanPasswordInput(in); err != nil {
		return err
	}

	listed, err := c.api.UserServiceV2().ListUsers(ctx, &userV2.ListUsersRequest{})
	if err != nil {
		return fmt.Errorf("admin.ResetHumanPassword: list users: %w", err)
	}
	username := strings.TrimSpace(in.Username)
	user, err := findHumanUser(listed.GetResult(), username)
	if err != nil {
		return fmt.Errorf("admin.ResetHumanPassword: %w", err)
	}
	if user == nil {
		return fmt.Errorf("admin.ResetHumanPassword: %w: %q", ErrUserNotFound, username)
	}

	if _, err := c.api.UserServiceV2().SetPassword(ctx, newSetPasswordRequest(user.GetUserId(), in)); err != nil {
		return fmt.Errorf("admin.ResetHumanPassword: set password: %w", err)
	}
	c.logger.Info("reset Zitadel human password", "username", username, "user_id", user.GetUserId(), "password_change_required", in.PasswordChangeRequired)
	return nil
}

func (c *Client) ensureHumanUser(ctx context.Context, orgID string, in HumanOnboardInput) (*userV2.User, bool, error) {
	listed, err := c.api.UserServiceV2().ListUsers(ctx, &userV2.ListUsersRequest{})
	if err != nil {
		return nil, false, err
	}
	user, err := findHumanUser(listed.GetResult(), strings.TrimSpace(in.Username))
	if err != nil {
		return nil, false, err
	}
	if user != nil {
		return user, false, nil
	}

	created, err := c.api.UserServiceV2().CreateUser(ctx, newHumanCreateRequest(orgID, in))
	if err != nil {
		return nil, false, err
	}
	got, err := c.api.UserServiceV2().GetUserByID(ctx, &userV2.GetUserByIDRequest{UserId: created.GetId()})
	if err != nil {
		return nil, false, err
	}
	user = got.GetUser()
	if user == nil || user.GetHuman() == nil {
		return nil, false, fmt.Errorf("%w: created user %q is not human", ErrUserTypeMismatch, strings.TrimSpace(in.Username))
	}
	return user, true, nil
}

func findHumanUser(users []*userV2.User, username string) (*userV2.User, error) {
	for _, user := range users {
		if user.GetUsername() != username {
			continue
		}
		if user.GetHuman() == nil {
			return nil, fmt.Errorf("%w: username %q belongs to a non-human user", ErrUserTypeMismatch, username)
		}
		return user, nil
	}
	return nil, nil
}

func newHumanCreateRequest(orgID string, in HumanOnboardInput) *userV2.CreateUserRequest {
	displayName := strings.TrimSpace(in.DisplayName)
	if displayName == "" {
		displayName = strings.TrimSpace(in.GivenName) + " " + strings.TrimSpace(in.FamilyName)
	}
	profile := &userV2.SetHumanProfile{
		GivenName:   strings.TrimSpace(in.GivenName),
		FamilyName:  strings.TrimSpace(in.FamilyName),
		DisplayName: strPtr(displayName),
	}
	email := &userV2.SetHumanEmail{Email: strings.TrimSpace(in.Email)}
	if in.EmailVerified {
		email.Verification = &userV2.SetHumanEmail_IsVerified{IsVerified: true}
	}

	return &userV2.CreateUserRequest{
		OrganizationId: orgID,
		Username:       strPtr(strings.TrimSpace(in.Username)),
		UserType: &userV2.CreateUserRequest_Human_{
			Human: &userV2.CreateUserRequest_Human{
				Profile: profile,
				Email:   email,
				PasswordType: &userV2.CreateUserRequest_Human_Password{
					Password: &userV2.Password{
						Password:       in.InitialPassword,
						ChangeRequired: in.PasswordChangeRequired,
					},
				},
			},
		},
	}
}

func humanLoginName(user *userV2.User) string {
	if preferred := strings.TrimSpace(user.GetPreferredLoginName()); preferred != "" {
		return preferred
	}
	return user.GetUsername()
}

func newSetPasswordRequest(userID string, in ResetHumanPasswordInput) *userV2.SetPasswordRequest {
	return &userV2.SetPasswordRequest{
		UserId: userID,
		NewPassword: &userV2.Password{
			Password:       in.NewPassword,
			ChangeRequired: in.PasswordChangeRequired,
		},
	}
}

func validateResetHumanPasswordInput(in ResetHumanPasswordInput) error {
	if strings.TrimSpace(in.Username) == "" {
		return fmt.Errorf("admin.ResetHumanPassword: Username is required")
	}
	if in.NewPassword == "" {
		return fmt.Errorf("admin.ResetHumanPassword: NewPassword is required")
	}
	return nil
}

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
