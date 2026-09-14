package admin

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"

	appV1 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/app"
	appV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/application/v2"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
)

type normalizedWebApplicationInput struct {
	name                   string
	redirectURIs           []string
	postLogoutRedirectURIs []string
	enableRefreshTokens    bool
	devMode                bool
}

func (c *Client) EnsureWebApplication(ctx context.Context, in WebApplicationInput) (*WebApplicationResult, error) {
	normalized, err := normalizeWebApplicationInput(in)
	if err != nil {
		return nil, err
	}
	project, err := c.resolveProject(ctx)
	if err != nil {
		return nil, fmt.Errorf("admin.EnsureWebApplication: resolve project: %w", err)
	}
	if project == nil {
		return nil, fmt.Errorf("admin.EnsureWebApplication: %w", ErrProjectNotConfigured)
	}

	app, err := c.lookupApplicationByName(ctx, project.GetProjectId(), normalized.name)
	if err != nil {
		return nil, fmt.Errorf("admin.EnsureWebApplication: lookup application: %w", err)
	}
	if app == nil {
		created, err := c.api.applications.CreateApplication(ctx, newWebApplicationCreateRequest(project.GetProjectId(), normalized))
		if err != nil {
			return nil, fmt.Errorf("admin.EnsureWebApplication: create application: %w", err)
		}
		result := &WebApplicationResult{
			ApplicationID: created.GetApplicationId(),
			ClientID:      created.GetOidcConfiguration().GetClientId(),
			Created:       true,
		}
		c.logWebApplication(project.GetProjectId(), normalized.name, result)
		return result, nil
	}

	oidc := app.GetOidcConfiguration()
	if oidc == nil {
		return nil, fmt.Errorf("admin.EnsureWebApplication: %w: application %q is not an OIDC application", ErrApplicationTypeMismatch, normalized.name)
	}
	result := &WebApplicationResult{ApplicationID: app.GetApplicationId(), ClientID: oidc.GetClientId()}
	if !webApplicationMatches(oidc, normalized) {
		if _, err := c.api.management.UpdateOIDCAppConfig(ctx, newWebApplicationUpdateRequest(project.GetProjectId(), app.GetApplicationId(), normalized)); err != nil {
			return nil, fmt.Errorf("admin.EnsureWebApplication: update application: %w", err)
		}
		result.Updated = true
	}
	c.logWebApplication(project.GetProjectId(), normalized.name, result)
	return result, nil
}

func (c *Client) logWebApplication(projectID, name string, result *WebApplicationResult) {
	if c.logger == nil {
		return
	}
	c.logger.Info("reconciled Zitadel Web/OIDC application", "project_id", projectID, "application_id", result.ApplicationID, "name", name, "created", result.Created, "updated", result.Updated)
}

func normalizeWebApplicationInput(in WebApplicationInput) (normalizedWebApplicationInput, error) {
	normalized := normalizedWebApplicationInput{
		name:                strings.TrimSpace(in.Name),
		enableRefreshTokens: in.EnableRefreshTokens,
		devMode:             in.DevMode,
	}
	if normalized.name == "" {
		return normalizedWebApplicationInput{}, fmt.Errorf("admin.EnsureWebApplication: Name is required")
	}
	if len(in.RedirectURIs) == 0 {
		return normalizedWebApplicationInput{}, fmt.Errorf("admin.EnsureWebApplication: at least one RedirectURI is required")
	}

	var err error
	normalized.redirectURIs, err = normalizeWebURISet("RedirectURIs", in.RedirectURIs, in.DevMode)
	if err != nil {
		return normalizedWebApplicationInput{}, err
	}
	normalized.postLogoutRedirectURIs, err = normalizeWebURISet("PostLogoutRedirectURIs", in.PostLogoutRedirectURIs, in.DevMode)
	if err != nil {
		return normalizedWebApplicationInput{}, err
	}
	return normalized, nil
}

func normalizeWebURISet(field string, values []string, devMode bool) ([]string, error) {
	normalized := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		uri, err := normalizeWebURI(value, devMode)
		if err != nil {
			return nil, fmt.Errorf("admin.EnsureWebApplication: %s: %w", field, err)
		}
		if _, duplicate := seen[uri]; duplicate {
			return nil, fmt.Errorf("admin.EnsureWebApplication: %s contains duplicate URI %q", field, uri)
		}
		seen[uri] = struct{}{}
		normalized = append(normalized, uri)
	}
	sort.Strings(normalized)
	return normalized, nil
}

func normalizeWebURI(value string, devMode bool) (string, error) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return "", fmt.Errorf("URI must not be empty")
	}
	lowerRaw := strings.ToLower(raw)
	if strings.Contains(raw, "*") || strings.Contains(lowerRaw, "%2a") {
		return "", fmt.Errorf("URI %q must not contain wildcards", raw)
	}
	if strings.Contains(raw, "#") {
		return "", fmt.Errorf("URI %q must not contain a fragment", raw)
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("URI %q is invalid: %w", raw, err)
	}
	if !parsed.IsAbs() || parsed.Host == "" || parsed.Opaque != "" {
		return "", fmt.Errorf("URI %q must be absolute and include a host", raw)
	}
	if parsed.User != nil {
		return "", fmt.Errorf("URI %q must not contain user information", raw)
	}
	if parsed.Fragment != "" || parsed.RawFragment != "" {
		return "", fmt.Errorf("URI %q must not contain a fragment", raw)
	}

	parsed.Scheme = strings.ToLower(parsed.Scheme)
	hostname := strings.ToLower(parsed.Hostname())
	if hostname == "" {
		return "", fmt.Errorf("URI %q must include a host", raw)
	}
	if parsed.Scheme != "https" {
		if parsed.Scheme != "http" || !devMode || !isLoopbackHost(hostname) {
			return "", fmt.Errorf("URI %q must use HTTPS; development HTTP is limited to loopback hosts", raw)
		}
	}
	if port := parsed.Port(); port != "" {
		parsed.Host = net.JoinHostPort(hostname, port)
	} else if strings.Contains(hostname, ":") {
		parsed.Host = "[" + hostname + "]"
	} else {
		parsed.Host = hostname
	}

	return parsed.String(), nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func newWebApplicationCreateRequest(projectID string, in normalizedWebApplicationInput) *appV2.CreateApplicationRequest {
	return &appV2.CreateApplicationRequest{
		ProjectId: projectID,
		Name:      in.name,
		ApplicationType: &appV2.CreateApplicationRequest_OidcConfiguration{
			OidcConfiguration: &appV2.CreateOIDCApplicationRequest{
				RedirectUris:           append([]string(nil), in.redirectURIs...),
				ResponseTypes:          []appV2.OIDCResponseType{appV2.OIDCResponseType_OIDC_RESPONSE_TYPE_CODE},
				GrantTypes:             webApplicationGrantTypes(in.enableRefreshTokens),
				ApplicationType:        appV2.OIDCApplicationType_OIDC_APP_TYPE_WEB,
				AuthMethodType:         appV2.OIDCAuthMethodType_OIDC_AUTH_METHOD_TYPE_NONE,
				PostLogoutRedirectUris: append([]string(nil), in.postLogoutRedirectURIs...),
				Version:                appV2.OIDCVersion_OIDC_VERSION_1_0,
				DevelopmentMode:        in.devMode,
				AccessTokenType:        appV2.OIDCTokenType_OIDC_TOKEN_TYPE_BEARER,
			},
		},
	}
}

func newWebApplicationUpdateRequest(projectID, applicationID string, in normalizedWebApplicationInput) *management.UpdateOIDCAppConfigRequest {
	grantTypes := []appV1.OIDCGrantType{appV1.OIDCGrantType_OIDC_GRANT_TYPE_AUTHORIZATION_CODE}
	if in.enableRefreshTokens {
		grantTypes = append(grantTypes, appV1.OIDCGrantType_OIDC_GRANT_TYPE_REFRESH_TOKEN)
	}
	return &management.UpdateOIDCAppConfigRequest{
		ProjectId:                projectID,
		AppId:                    applicationID,
		RedirectUris:             append([]string(nil), in.redirectURIs...),
		ResponseTypes:            []appV1.OIDCResponseType{appV1.OIDCResponseType_OIDC_RESPONSE_TYPE_CODE},
		GrantTypes:               grantTypes,
		AppType:                  appV1.OIDCAppType_OIDC_APP_TYPE_WEB,
		AuthMethodType:           appV1.OIDCAuthMethodType_OIDC_AUTH_METHOD_TYPE_NONE,
		PostLogoutRedirectUris:   append([]string(nil), in.postLogoutRedirectURIs...),
		DevMode:                  in.devMode,
		AccessTokenType:          appV1.OIDCTokenType_OIDC_TOKEN_TYPE_BEARER,
		AccessTokenRoleAssertion: false,
		IdTokenRoleAssertion:     false,
		IdTokenUserinfoAssertion: false,
	}
}

func webApplicationMatches(actual *appV2.OIDCConfiguration, desired normalizedWebApplicationInput) bool {
	return sameMembers(actual.GetRedirectUris(), desired.redirectURIs) &&
		sameMembers(actual.GetResponseTypes(), []appV2.OIDCResponseType{appV2.OIDCResponseType_OIDC_RESPONSE_TYPE_CODE}) &&
		sameMembers(actual.GetGrantTypes(), webApplicationGrantTypes(desired.enableRefreshTokens)) &&
		actual.GetApplicationType() == appV2.OIDCApplicationType_OIDC_APP_TYPE_WEB &&
		actual.GetAuthMethodType() == appV2.OIDCAuthMethodType_OIDC_AUTH_METHOD_TYPE_NONE &&
		sameMembers(actual.GetPostLogoutRedirectUris(), desired.postLogoutRedirectURIs) &&
		actual.GetVersion() == appV2.OIDCVersion_OIDC_VERSION_1_0 &&
		actual.GetDevelopmentMode() == desired.devMode &&
		actual.GetAccessTokenType() == appV2.OIDCTokenType_OIDC_TOKEN_TYPE_BEARER &&
		!actual.GetAccessTokenRoleAssertion() &&
		!actual.GetIdTokenRoleAssertion() &&
		!actual.GetIdTokenUserinfoAssertion()
}

func webApplicationGrantTypes(enableRefreshTokens bool) []appV2.OIDCGrantType {
	grantTypes := []appV2.OIDCGrantType{appV2.OIDCGrantType_OIDC_GRANT_TYPE_AUTHORIZATION_CODE}
	if enableRefreshTokens {
		grantTypes = append(grantTypes, appV2.OIDCGrantType_OIDC_GRANT_TYPE_REFRESH_TOKEN)
	}
	return grantTypes
}

func sameMembers[T comparable](left, right []T) bool {
	if len(left) != len(right) {
		return false
	}
	counts := make(map[T]int, len(left))
	for _, value := range left {
		counts[value]++
	}
	for _, value := range right {
		if counts[value] == 0 {
			return false
		}
		counts[value]--
	}
	return true
}
