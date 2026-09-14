package admin

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	authzV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/authorization/v2"
	projV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/project/v2"
	userV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	"google.golang.org/grpc/codes"
)

func (c *Client) Onboard(ctx context.Context, in OnboardInput) (*OnboardResult, error) {
	if strings.TrimSpace(in.Username) == "" {
		return nil, fmt.Errorf("admin.Onboard: Username is required")
	}
	for _, p := range in.Permissions {
		if err := validatePermission(strings.TrimSpace(p)); err != nil {
			return nil, fmt.Errorf("admin.Onboard: %w", err)
		}
	}
	if err := validatePatterns(in.KeyAccess.AllowedKeyPatterns, in.KeyAccess.DenyKeyPatterns, in.PolicyAccess.AllowedPolicyPatterns, in.PolicyAccess.DenyPolicyPatterns); err != nil {
		return nil, err
	}

	project, err := c.resolveProject(ctx)
	if err != nil {
		return nil, fmt.Errorf("admin.Onboard: resolve project: %w", err)
	}
	orgID, err := c.resolveOrgID(ctx)
	if err != nil {
		return nil, fmt.Errorf("admin.Onboard: resolve org: %w", err)
	}

	user, created, err := c.ensureMachineUser(ctx, orgID, in)
	if err != nil {
		return nil, fmt.Errorf("admin.Onboard: ensure machine user: %w", err)
	}

	result := &OnboardResult{UserID: user.GetUserId(), ClientID: user.GetPreferredLoginName()}
	if created {
		secretResp, err := c.api.users.AddSecret(ctx, &userV2.AddSecretRequest{UserId: user.GetUserId()})
		if err != nil {
			return nil, fmt.Errorf("admin.Onboard: mint client secret: %w", err)
		}
		result.ClientSecret = secretResp.GetClientSecret()
	}

	if err := c.reconcileAuthorizations(ctx, orgID, project.GetProjectId(), user.GetUserId(), in.Permissions); err != nil {
		return nil, fmt.Errorf("admin.Onboard: reconcile authorizations: %w", err)
	}
	if err := c.reconcileMetadata(ctx, user.GetUserId(), in.KeyAccess, in.PolicyAccess); err != nil {
		return nil, fmt.Errorf("admin.Onboard: reconcile metadata: %w", err)
	}

	c.logger.Info("onboarded Zitadel machine user", "username", in.Username, "user_id", result.UserID, "project_id", project.GetProjectId())
	return result, nil
}

func (c *Client) ensureMachineUser(ctx context.Context, orgID string, in OnboardInput) (*userV2.User, bool, error) {
	// NOTE: ListUsers returns one page (default size, currently 100 in
	// Zitadel). For organisations with more users than fit in a single
	// page this lookup must be replaced with a server-side filter on
	// username. Tracked as a follow-up; safe for the bootstrap-sized
	// orgs this admin package targets today.
	listed, err := c.api.users.ListUsers(ctx, &userV2.ListUsersRequest{})
	if err != nil {
		return nil, false, err
	}
	for _, user := range listed.GetResult() {
		if user.GetUsername() == in.Username {
			return user, false, nil
		}
	}

	displayName := strings.TrimSpace(in.DisplayName)
	if displayName == "" {
		displayName = in.Username
	}
	description := fmt.Sprintf("managed by zitadel-grpc-auth admin for %s", displayName)
	created, err := c.api.users.CreateUser(ctx, &userV2.CreateUserRequest{
		OrganizationId: orgID,
		Username:       strPtr(in.Username),
		UserType: &userV2.CreateUserRequest_Machine_{
			Machine: &userV2.CreateUserRequest_Machine{
				Name:            displayName,
				Description:     &description,
				AccessTokenType: userV2.AccessTokenType_ACCESS_TOKEN_TYPE_BEARER,
			},
		},
	})
	if err != nil {
		return nil, false, err
	}
	got, err := c.api.users.GetUserByID(ctx, &userV2.GetUserByIDRequest{UserId: created.GetId()})
	if err != nil {
		return nil, false, err
	}
	return got.GetUser(), true, nil
}

func (c *Client) reconcileAuthorizations(ctx context.Context, orgID, projectID, userID string, permissions []string) error {
	desired := normalizeSortedStrings(permissions)
	listed, err := c.api.authorizations.ListAuthorizations(ctx, &authzV2.ListAuthorizationsRequest{})
	if err != nil {
		return err
	}

	matching := make([]*authzV2.Authorization, 0)
	current := make(map[string]struct{})
	for _, authz := range listed.GetAuthorizations() {
		if authz.GetUser().GetId() != userID || authz.GetProject().GetId() != projectID {
			continue
		}
		matching = append(matching, authz)
		for _, role := range authz.GetRoles() {
			current[role.GetKey()] = struct{}{}
		}
	}

	if sameRoleSet(current, desired) && len(matching) <= 1 {
		return nil
	}
	for _, authz := range matching {
		_, err := c.api.authorizations.DeleteAuthorization(ctx, &authzV2.DeleteAuthorizationRequest{Id: authz.GetId()})
		if err != nil && !isStatusCode(err, codes.NotFound) {
			return err
		}
	}
	if len(desired) == 0 {
		return nil
	}
	_, err = c.api.authorizations.CreateAuthorization(ctx, &authzV2.CreateAuthorizationRequest{
		OrganizationId: orgID,
		UserId:         userID,
		ProjectId:      projectID,
		RoleKeys:       desired,
	})
	return err
}

func (c *Client) reconcileMetadata(ctx context.Context, userID string, keyAccess KeyAccess, policyAccess PolicyAccess) error {
	namespace := normalizeNamespace("", c.cfg.Namespace)
	toSet := make([]*userV2.Metadata, 0, 2)
	toDelete := make([]string, 0, 2)

	if hasKeyAccess(keyAccess) {
		payload, err := marshalKeyAccess(keyAccess)
		if err != nil {
			return err
		}
		toSet = append(toSet, &userV2.Metadata{Key: keyAccessMetadataKey(namespace), Value: payload})
	} else {
		toDelete = append(toDelete, keyAccessMetadataKey(namespace))
	}

	if hasPolicyAccess(policyAccess) {
		payload, err := marshalPolicyAccess(policyAccess)
		if err != nil {
			return err
		}
		toSet = append(toSet, &userV2.Metadata{Key: policyAccessMetadataKey(namespace), Value: payload})
	} else {
		toDelete = append(toDelete, policyAccessMetadataKey(namespace))
	}

	if len(toSet) > 0 {
		_, err := c.api.users.SetUserMetadata(ctx, &userV2.SetUserMetadataRequest{UserId: userID, Metadata: toSet})
		if err != nil {
			return err
		}
	}
	if len(toDelete) > 0 {
		_, err := c.api.users.DeleteUserMetadata(ctx, &userV2.DeleteUserMetadataRequest{UserId: userID, Keys: toDelete})
		if err != nil && !isStatusCode(err, codes.NotFound) {
			return err
		}
	}
	return nil
}

func (c *Client) resolveOrgID(ctx context.Context) (string, error) {
	if strings.TrimSpace(c.cfg.OrgID) != "" {
		return c.cfg.OrgID, nil
	}
	resp, err := c.api.organizations.ListOrganizations(ctx, nil)
	if err != nil {
		return "", err
	}
	if len(resp.GetResult()) == 0 {
		return "", fmt.Errorf("no organizations returned")
	}
	return resp.GetResult()[0].GetId(), nil
}

func (c *Client) resolveProject(ctx context.Context) (*projV2.Project, error) {
	orgID, err := c.resolveOrgID(ctx)
	if err != nil {
		return nil, err
	}
	projects, err := c.api.projects.ListProjects(ctx, &projV2.ListProjectsRequest{})
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(c.cfg.ProjectID) != "" {
		for _, project := range projects.GetProjects() {
			if project.GetProjectId() == c.cfg.ProjectID {
				return project, nil
			}
		}
		return nil, ErrProjectNotConfigured
	}
	if strings.TrimSpace(c.cfg.ProjectName) != "" {
		return c.findProjectByName(ctx, orgID, c.cfg.ProjectName)
	}
	matching := make([]*projV2.Project, 0)
	for _, project := range projects.GetProjects() {
		if project.GetOrganizationId() == orgID {
			matching = append(matching, project)
		}
	}
	if len(matching) == 1 {
		return matching[0], nil
	}
	return nil, ErrProjectNotConfigured
}

func (c *Client) findProjectByName(ctx context.Context, orgID, projectName string) (*projV2.Project, error) {
	resp, err := c.api.projects.ListProjects(ctx, &projV2.ListProjectsRequest{})
	if err != nil {
		return nil, err
	}
	for _, project := range resp.GetProjects() {
		if project.GetOrganizationId() == orgID && project.GetName() == projectName {
			return project, nil
		}
	}
	return nil, nil
}

func validatePatterns(groups ...[]string) error {
	for _, group := range groups {
		for _, pattern := range group {
			if pattern == "" {
				return fmt.Errorf("%w: empty pattern", ErrInvalidPattern)
			}
			if _, err := filepath.Match(pattern, "probe"); err != nil {
				return fmt.Errorf("%w: %q: %v", ErrInvalidPattern, pattern, err)
			}
			// Restrict to a printable, non-whitespace ASCII subset. The
			// pattern is later embedded in JSON metadata that flows
			// through Zitadel and back into a token claim — anything
			// goes structurally, but constraining the character set
			// makes audit trails legible and stops accidental injection
			// of newlines, control characters, or quoting tricks into
			// downstream logs and policy decisions.
			for _, r := range pattern {
				switch {
				case r >= 'a' && r <= 'z':
				case r >= 'A' && r <= 'Z':
				case r >= '0' && r <= '9':
				case r == '*' || r == '-' || r == '_' || r == '.' || r == ':' || r == '/':
				default:
					return fmt.Errorf("%w: %q contains disallowed character %q (allowed: alphanumerics and *-_.:/ )", ErrInvalidPattern, pattern, r)
				}
			}
		}
	}
	return nil
}

// validatePermission restricts permission/role keys to the same character
// set we apply to namespaces. Permissions become Zitadel project role keys
// and end up inside a token claim consulted by policies; anything outside
// this character set is almost always either a typo or an attempt to
// smuggle structure through a field that downstream code treats as a
// plain string.
func validatePermission(p string) error {
	if p == "" {
		return fmt.Errorf("admin: permission must not be empty")
	}
	for _, r := range p {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == ':' || r == '-' || r == '_' || r == '.':
		default:
			return fmt.Errorf("admin: permission %q contains disallowed character %q (allowed: alphanumerics and :-_.)", p, r)
		}
	}
	return nil
}

func normalizeSortedStrings(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		set[trimmed] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func sameRoleSet(current map[string]struct{}, desired []string) bool {
	if len(current) != len(desired) {
		return false
	}
	for _, role := range desired {
		if _, ok := current[role]; !ok {
			return false
		}
	}
	return true
}

func strPtr(s string) *string { return &s }
