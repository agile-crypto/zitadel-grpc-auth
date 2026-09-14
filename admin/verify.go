package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/mail"
	"sort"
	"strconv"
	"strings"
	"time"

	actionV1 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/action"
	appV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/application/v2"
	authzV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/authorization/v2"
	filterV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/filter/v2"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
	userV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	"google.golang.org/grpc/codes"
)

const (
	humanTokenFlowType    = "2"
	humanTokenTriggerType = "4"
)

func (c *Client) VerifyHumanAuthConfiguration(ctx context.Context, in HumanAuthConfigurationInput) (*HumanAuthConfigurationResult, error) {
	namespace := normalizeNamespace(in.ClaimNamespace, c.cfg.Namespace)
	if err := validateNamespace(namespace); err != nil {
		return nil, fmt.Errorf("admin.VerifyHumanAuthConfiguration: %w", err)
	}
	if err := validateHumanConfigurations(in.Humans); err != nil {
		return nil, err
	}
	web, err := normalizeWebApplicationInput(in.WebApplication)
	if err != nil {
		return nil, fmt.Errorf("admin.VerifyHumanAuthConfiguration: WebApplication: %w", err)
	}

	project, err := c.resolveProject(ctx)
	if err != nil {
		return nil, fmt.Errorf("admin.VerifyHumanAuthConfiguration: resolve project: %w", err)
	}
	if project == nil {
		return nil, fmt.Errorf("admin.VerifyHumanAuthConfiguration: %w", ErrProjectNotConfigured)
	}
	orgID, err := c.resolveOrgID(ctx)
	if err != nil {
		return nil, fmt.Errorf("admin.VerifyHumanAuthConfiguration: resolve org: %w", err)
	}

	result := &HumanAuthConfigurationResult{ProjectID: project.GetProjectId()}
	if !project.GetProjectRoleAssertion() {
		result.addDrift("project/"+project.GetProjectId(), "project_role_assertion", true, false)
	}
	if err := c.verifyClaimAction(ctx, namespace, result); err != nil {
		return nil, fmt.Errorf("admin.VerifyHumanAuthConfiguration: verify claim action: %w", err)
	}
	if err := c.verifyWebApplication(ctx, project.GetProjectId(), web, result); err != nil {
		return nil, fmt.Errorf("admin.VerifyHumanAuthConfiguration: verify web application: %w", err)
	}

	authorizations, err := c.listAllAuthorizations(ctx)
	if err != nil {
		return nil, fmt.Errorf("admin.VerifyHumanAuthConfiguration: list authorizations: %w", err)
	}
	for _, expected := range in.Humans {
		if err := c.verifyHuman(ctx, orgID, project.GetProjectId(), namespace, expected, authorizations, result); err != nil {
			return nil, fmt.Errorf("admin.VerifyHumanAuthConfiguration: verify human %q: %w", strings.TrimSpace(expected.Username), err)
		}
	}

	result.Current = len(result.Drift) == 0
	return result, nil
}

func validateHumanConfigurations(humans []HumanConfiguration) error {
	seen := make(map[string]struct{}, len(humans))
	for i, human := range humans {
		required := []struct {
			name  string
			value string
		}{
			{name: "Username", value: human.Username},
			{name: "GivenName", value: human.GivenName},
			{name: "FamilyName", value: human.FamilyName},
			{name: "Email", value: human.Email},
		}
		for _, field := range required {
			if strings.TrimSpace(field.value) == "" {
				return fmt.Errorf("admin.VerifyHumanAuthConfiguration: Humans[%d].%s is required", i, field.name)
			}
		}
		username := strings.TrimSpace(human.Username)
		if _, duplicate := seen[username]; duplicate {
			return fmt.Errorf("admin.VerifyHumanAuthConfiguration: duplicate human Username %q", username)
		}
		seen[username] = struct{}{}
		address, err := mail.ParseAddress(human.Email)
		if err != nil || address.Address != human.Email {
			return fmt.Errorf("admin.VerifyHumanAuthConfiguration: Humans[%d].Email must be a valid address", i)
		}
		for _, permission := range human.Permissions {
			if err := validatePermission(strings.TrimSpace(permission)); err != nil {
				return fmt.Errorf("admin.VerifyHumanAuthConfiguration: Humans[%d]: %w", i, err)
			}
		}
		if err := validatePatterns(
			human.KeyAccess.AllowedKeyPatterns,
			human.KeyAccess.DenyKeyPatterns,
			human.PolicyAccess.AllowedPolicyPatterns,
			human.PolicyAccess.DenyPolicyPatterns,
		); err != nil {
			return fmt.Errorf("admin.VerifyHumanAuthConfiguration: Humans[%d]: %w", i, err)
		}
	}
	return nil
}

func (c *Client) verifyClaimAction(ctx context.Context, namespace string, result *HumanAuthConfigurationResult) error {
	name := actionNameForNamespace(namespace)
	resource := "action/" + name
	expectedScript, err := RenderActionScript(namespace)
	if err != nil {
		return err
	}
	listed, err := c.api.management.ListActions(ctx, &management.ListActionsRequest{})
	if err != nil {
		return err
	}
	var matches []*actionV1.Action
	for _, action := range listed.GetResult() {
		if action.GetName() == name {
			matches = append(matches, action)
		}
	}
	if len(matches) == 0 {
		result.addDrift(resource, "exists", true, false)
		return nil
	}
	if len(matches) != 1 {
		result.addDrift(resource, "count", 1, len(matches))
		return nil
	}
	action := matches[0]
	result.compare(resource, "state", actionV1.ActionState_ACTION_STATE_ACTIVE.String(), action.GetState().String())
	result.compare(resource, "script", expectedScript, action.GetScript())
	result.compare(resource, "timeout", (10 * time.Second).String(), action.GetTimeout().AsDuration().String())
	result.compare(resource, "allowed_to_fail", false, action.GetAllowedToFail())

	flow, err := c.api.management.GetFlow(ctx, &management.GetFlowRequest{Type: humanTokenFlowType})
	if err != nil {
		if isStatusCode(err, codes.NotFound) {
			result.addDrift(resource, "token_flow_trigger", "wired", "missing")
			return nil
		}
		return err
	}
	wired := false
	for _, trigger := range flow.GetFlow().GetTriggerActions() {
		if trigger.GetTriggerType().GetId() != humanTokenTriggerType {
			continue
		}
		for _, candidate := range trigger.GetActions() {
			if candidate.GetId() == action.GetId() {
				wired = true
			}
		}
	}
	result.compare(resource, "token_flow_trigger", true, wired)
	return nil
}

func (c *Client) verifyWebApplication(ctx context.Context, projectID string, expected normalizedWebApplicationInput, result *HumanAuthConfigurationResult) error {
	resource := "application/" + expected.name
	application, err := c.lookupApplicationByName(ctx, projectID, expected.name)
	if err != nil {
		return err
	}
	if application == nil {
		result.addDrift(resource, "exists", true, false)
		return nil
	}
	oidc := application.GetOidcConfiguration()
	if oidc == nil {
		result.addDrift(resource, "type", "OIDC", applicationType(application))
		return nil
	}
	result.compareSet(resource, "redirect_uris", expected.redirectURIs, oidc.GetRedirectUris())
	result.compareSet(resource, "response_types", []appV2.OIDCResponseType{appV2.OIDCResponseType_OIDC_RESPONSE_TYPE_CODE}, oidc.GetResponseTypes())
	result.compareSet(resource, "grant_types", webApplicationGrantTypes(expected.enableRefreshTokens), oidc.GetGrantTypes())
	result.compare(resource, "application_type", appV2.OIDCApplicationType_OIDC_APP_TYPE_WEB.String(), oidc.GetApplicationType().String())
	result.compare(resource, "auth_method_type", appV2.OIDCAuthMethodType_OIDC_AUTH_METHOD_TYPE_NONE.String(), oidc.GetAuthMethodType().String())
	result.compareSet(resource, "post_logout_redirect_uris", expected.postLogoutRedirectURIs, oidc.GetPostLogoutRedirectUris())
	result.compare(resource, "version", appV2.OIDCVersion_OIDC_VERSION_1_0.String(), oidc.GetVersion().String())
	result.compare(resource, "development_mode", expected.devMode, oidc.GetDevelopmentMode())
	result.compare(resource, "access_token_type", appV2.OIDCTokenType_OIDC_TOKEN_TYPE_BEARER.String(), oidc.GetAccessTokenType().String())
	result.compare(resource, "access_token_role_assertion", false, oidc.GetAccessTokenRoleAssertion())
	result.compare(resource, "id_token_role_assertion", false, oidc.GetIdTokenRoleAssertion())
	result.compare(resource, "id_token_userinfo_assertion", false, oidc.GetIdTokenUserinfoAssertion())
	return nil
}

func applicationType(application *appV2.Application) string {
	switch {
	case application.GetApiConfiguration() != nil:
		return "API"
	case application.GetSamlConfiguration() != nil:
		return "SAML"
	default:
		return "unknown"
	}
}

func (c *Client) verifyHuman(ctx context.Context, orgID, projectID, namespace string, expected HumanConfiguration, authorizations []*authzV2.Authorization, result *HumanAuthConfigurationResult) error {
	username := strings.TrimSpace(expected.Username)
	resource := "human/" + username
	user, err := c.lookupUserByUsername(ctx, orgID, username)
	if err != nil {
		return err
	}
	if user == nil {
		result.addDrift(resource, "exists", true, false)
		return nil
	}
	human := user.GetHuman()
	if human == nil {
		actualType := "unknown"
		if user.GetMachine() != nil {
			actualType = "machine"
		}
		result.addDrift(resource, "type", "human", actualType)
		return nil
	}
	if user.GetState() != userV2.UserState_USER_STATE_ACTIVE && user.GetState() != userV2.UserState_USER_STATE_INITIAL {
		result.addDrift(resource, "state", "ACTIVE or INITIAL", user.GetState().String())
	}
	profile := human.GetProfile()
	result.compare(resource, "profile.given_name", strings.TrimSpace(expected.GivenName), profile.GetGivenName())
	result.compare(resource, "profile.family_name", strings.TrimSpace(expected.FamilyName), profile.GetFamilyName())
	displayName := strings.TrimSpace(expected.DisplayName)
	if displayName == "" {
		displayName = strings.TrimSpace(expected.GivenName) + " " + strings.TrimSpace(expected.FamilyName)
	}
	result.compare(resource, "profile.display_name", displayName, profile.GetDisplayName())
	result.compare(resource, "email.address", strings.TrimSpace(expected.Email), human.GetEmail().GetEmail())
	result.compare(resource, "email.verified", expected.EmailVerified, human.GetEmail().GetIsVerified())
	result.compare(resource, "password_change_required", expected.PasswordChangeRequired, human.GetPasswordChangeRequired())
	verifyRoles(user.GetUserId(), projectID, expected.Permissions, authorizations, resource, result)

	metadata, err := c.listAllUserMetadata(ctx, user.GetUserId())
	if err != nil {
		return err
	}
	verifyAccessMetadata(namespace, expected, metadata, resource, result)
	return nil
}

func (c *Client) listAllAuthorizations(ctx context.Context) ([]*authzV2.Authorization, error) {
	var all []*authzV2.Authorization
	var offset uint64
	for {
		resp, err := c.api.authorizations.ListAuthorizations(ctx, &authzV2.ListAuthorizationsRequest{
			Pagination: &filterV2.PaginationRequest{Offset: offset, Limit: lookupPageSize, Asc: true},
		})
		if err != nil {
			return nil, err
		}
		all = append(all, resp.GetAuthorizations()...)
		next := offset + uint64(len(resp.GetAuthorizations()))
		if paginationComplete(next, len(resp.GetAuthorizations()), resp.GetPagination().GetTotalResult()) {
			return all, nil
		}
		if next == offset {
			return nil, fmt.Errorf("authorization pagination did not advance")
		}
		offset = next
	}
}

func verifyRoles(userID, projectID string, expected []string, authorizations []*authzV2.Authorization, resource string, result *HumanAuthConfigurationResult) {
	var matching []*authzV2.Authorization
	roles := make(map[string]struct{})
	for _, authorization := range authorizations {
		if authorization.GetUser().GetId() != userID || authorization.GetProject().GetId() != projectID {
			continue
		}
		matching = append(matching, authorization)
		for _, role := range authorization.GetRoles() {
			roles[role.GetKey()] = struct{}{}
		}
	}
	want := normalizeSortedStrings(expected)
	wantCount := 0
	if len(want) > 0 {
		wantCount = 1
	}
	result.compare(resource, "authorization.count", wantCount, len(matching))
	if len(matching) == 1 {
		result.compare(resource, "authorization.state", authzV2.State_STATE_ACTIVE.String(), matching[0].GetState().String())
	}
	actual := make([]string, 0, len(roles))
	for role := range roles {
		actual = append(actual, role)
	}
	sort.Strings(actual)
	result.compare(resource, "roles", want, actual)
}

func (c *Client) listAllUserMetadata(ctx context.Context, userID string) (map[string][][]byte, error) {
	metadata := make(map[string][][]byte)
	var offset uint64
	for {
		resp, err := c.api.users.ListUserMetadata(ctx, &userV2.ListUserMetadataRequest{
			UserId:     userID,
			Pagination: &filterV2.PaginationRequest{Offset: offset, Limit: lookupPageSize, Asc: true},
		})
		if err != nil {
			return nil, err
		}
		for _, entry := range resp.GetMetadata() {
			metadata[entry.GetKey()] = append(metadata[entry.GetKey()], append([]byte(nil), entry.GetValue()...))
		}
		next := offset + uint64(len(resp.GetMetadata()))
		if paginationComplete(next, len(resp.GetMetadata()), resp.GetPagination().GetTotalResult()) {
			return metadata, nil
		}
		if next == offset {
			return nil, fmt.Errorf("metadata pagination did not advance")
		}
		offset = next
	}
}

func verifyAccessMetadata(namespace string, expected HumanConfiguration, actual map[string][][]byte, resource string, result *HumanAuthConfigurationResult) {
	keyPayload, _ := marshalKeyAccess(expected.KeyAccess)
	policyPayload, _ := marshalPolicyAccess(expected.PolicyAccess)
	verifyMetadataEntry(result, resource, keyAccessMetadataKey(namespace), hasKeyAccess(expected.KeyAccess), keyPayload, actual[keyAccessMetadataKey(namespace)])
	verifyMetadataEntry(result, resource, policyAccessMetadataKey(namespace), hasPolicyAccess(expected.PolicyAccess), policyPayload, actual[policyAccessMetadataKey(namespace)])
}

func verifyMetadataEntry(result *HumanAuthConfigurationResult, resource, key string, expectedPresent bool, expected []byte, actual [][]byte) {
	field := "metadata." + key
	if !expectedPresent {
		if len(actual) != 0 {
			result.addDrift(resource, field, "absent", "present")
		}
		return
	}
	if len(actual) == 0 {
		result.addDrift(resource, field, canonicalJSON(expected), "missing")
		return
	}
	if len(actual) != 1 {
		result.addDrift(resource, field+".count", 1, len(actual))
		return
	}
	result.compare(resource, field, canonicalJSON(expected), canonicalJSON(actual[0]))
}

func canonicalJSON(data []byte) string {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return "invalid JSON"
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "invalid JSON"
	}
	return string(encoded)
}

func (r *HumanAuthConfigurationResult) compare(resource, field string, expected, actual any) {
	want := driftValue(expected)
	got := driftValue(actual)
	if want != got {
		r.Drift = append(r.Drift, ConfigurationDrift{Resource: resource, Field: field, Expected: want, Actual: got})
	}
}

func (r *HumanAuthConfigurationResult) compareSet(resource, field string, expected, actual any) {
	r.compare(resource, field, sortedJSON(expected), sortedJSON(actual))
}

func (r *HumanAuthConfigurationResult) addDrift(resource, field string, expected, actual any) {
	r.Drift = append(r.Drift, ConfigurationDrift{
		Resource: resource,
		Field:    field,
		Expected: driftValue(expected),
		Actual:   driftValue(actual),
	})
}

func driftValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case bool:
		return strconv.FormatBool(typed)
	default:
		encoded, err := json.Marshal(value)
		if err != nil {
			return fmt.Sprint(value)
		}
		return string(encoded)
	}
}

func sortedJSON(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprint(value)
	}
	var values []any
	if err := json.Unmarshal(encoded, &values); err != nil {
		return string(encoded)
	}
	stringsValues := make([]string, 0, len(values))
	for _, item := range values {
		stringsValues = append(stringsValues, fmt.Sprint(item))
	}
	sort.Strings(stringsValues)
	return driftValue(stringsValues)
}
