package admin

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"

	appV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/application/v2"
)

type normalizedWebApplicationInput struct {
	name                   string
	redirectURIs           []string
	postLogoutRedirectURIs []string
	enableRefreshTokens    bool
	devMode                bool
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
	grantTypes := []appV2.OIDCGrantType{appV2.OIDCGrantType_OIDC_GRANT_TYPE_AUTHORIZATION_CODE}
	if in.enableRefreshTokens {
		grantTypes = append(grantTypes, appV2.OIDCGrantType_OIDC_GRANT_TYPE_REFRESH_TOKEN)
	}
	return &appV2.CreateApplicationRequest{
		ProjectId: projectID,
		Name:      in.name,
		ApplicationType: &appV2.CreateApplicationRequest_OidcConfiguration{
			OidcConfiguration: &appV2.CreateOIDCApplicationRequest{
				RedirectUris:           append([]string(nil), in.redirectURIs...),
				ResponseTypes:          []appV2.OIDCResponseType{appV2.OIDCResponseType_OIDC_RESPONSE_TYPE_CODE},
				GrantTypes:             grantTypes,
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
