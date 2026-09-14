package admin

import (
	"reflect"
	"strings"
	"testing"

	appV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/application/v2"
)

func TestNormalizeWebApplicationInput(t *testing.T) {
	in := WebApplicationInput{
		Name:                   " Citius Workbench ",
		RedirectURIs:           []string{"https://UI.EXAMPLE.test/auth/callback", "https://ui.example.test/second"},
		PostLogoutRedirectURIs: []string{"https://UI.EXAMPLE.test/"},
		EnableRefreshTokens:    true,
	}

	got, err := normalizeWebApplicationInput(in)
	if err != nil {
		t.Fatalf("normalizeWebApplicationInput: %v", err)
	}
	if got.name != "Citius Workbench" || !got.enableRefreshTokens || got.devMode {
		t.Fatalf("unexpected normalized scalar fields: %+v", got)
	}
	wantRedirects := []string{"https://ui.example.test/auth/callback", "https://ui.example.test/second"}
	if !reflect.DeepEqual(got.redirectURIs, wantRedirects) {
		t.Fatalf("redirect URIs = %v, want %v", got.redirectURIs, wantRedirects)
	}
	if want := []string{"https://ui.example.test/"}; !reflect.DeepEqual(got.postLogoutRedirectURIs, want) {
		t.Fatalf("post-logout redirect URIs = %v, want %v", got.postLogoutRedirectURIs, want)
	}
}

func TestNormalizeWebApplicationInputRejectsInvalidURIs(t *testing.T) {
	valid := WebApplicationInput{
		Name:                   "Citius Workbench",
		RedirectURIs:           []string{"https://ui.example.test/auth/callback"},
		PostLogoutRedirectURIs: []string{"https://ui.example.test/"},
	}
	tests := []struct {
		name    string
		mutate  func(*WebApplicationInput)
		wantErr string
	}{
		{name: "missing name", mutate: func(in *WebApplicationInput) { in.Name = " " }, wantErr: "Name is required"},
		{name: "missing redirects", mutate: func(in *WebApplicationInput) { in.RedirectURIs = nil }, wantErr: "at least one RedirectURI"},
		{name: "empty URI", mutate: func(in *WebApplicationInput) { in.RedirectURIs = []string{" "} }, wantErr: "must not be empty"},
		{name: "relative URI", mutate: func(in *WebApplicationInput) { in.RedirectURIs = []string{"/auth/callback"} }, wantErr: "must be absolute"},
		{name: "missing host", mutate: func(in *WebApplicationInput) { in.RedirectURIs = []string{"https:/auth/callback"} }, wantErr: "must be absolute"},
		{name: "fragment", mutate: func(in *WebApplicationInput) {
			in.RedirectURIs = []string{"https://ui.example.test/auth/callback#token"}
		}, wantErr: "must not contain a fragment"},
		{name: "empty fragment", mutate: func(in *WebApplicationInput) { in.RedirectURIs = []string{"https://ui.example.test/auth/callback#"} }, wantErr: "must not contain a fragment"},
		{name: "user information", mutate: func(in *WebApplicationInput) {
			in.RedirectURIs = []string{"https://user:password@ui.example.test/auth/callback"}
		}, wantErr: "must not contain user information"},
		{name: "wildcard", mutate: func(in *WebApplicationInput) { in.RedirectURIs = []string{"https://*.example.test/auth/callback"} }, wantErr: "must not contain wildcards"},
		{name: "encoded wildcard", mutate: func(in *WebApplicationInput) { in.RedirectURIs = []string{"https://ui.example.test/%2A"} }, wantErr: "must not contain wildcards"},
		{name: "production HTTP", mutate: func(in *WebApplicationInput) { in.RedirectURIs = []string{"http://localhost:7861/auth/callback"} }, wantErr: "must use HTTPS"},
		{name: "development non-loopback HTTP", mutate: func(in *WebApplicationInput) {
			in.DevMode = true
			in.RedirectURIs = []string{"http://ui.example.test/auth/callback"}
		}, wantErr: "limited to loopback hosts"},
		{name: "unsupported scheme", mutate: func(in *WebApplicationInput) { in.RedirectURIs = []string{"ftp://ui.example.test/auth/callback"} }, wantErr: "must use HTTPS"},
		{name: "normalized duplicate", mutate: func(in *WebApplicationInput) {
			in.RedirectURIs = []string{"https://UI.EXAMPLE.test/auth/callback", " https://ui.example.test/auth/callback "}
		}, wantErr: "duplicate URI"},
		{name: "invalid post-logout URI", mutate: func(in *WebApplicationInput) { in.PostLogoutRedirectURIs = []string{"/signed-out"} }, wantErr: "PostLogoutRedirectURIs"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := valid
			in.RedirectURIs = append([]string(nil), valid.RedirectURIs...)
			in.PostLogoutRedirectURIs = append([]string(nil), valid.PostLogoutRedirectURIs...)
			tt.mutate(&in)

			_, err := normalizeWebApplicationInput(in)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("normalizeWebApplicationInput error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestNormalizeWebApplicationInputAllowsDevelopmentLoopbackHTTP(t *testing.T) {
	for _, redirectURI := range []string{
		"http://localhost:7861/auth/callback",
		"http://127.0.0.1:7861/auth/callback",
		"http://[::1]:7861/auth/callback",
	} {
		t.Run(redirectURI, func(t *testing.T) {
			_, err := normalizeWebApplicationInput(WebApplicationInput{
				Name:         "Citius Workbench",
				RedirectURIs: []string{redirectURI},
				DevMode:      true,
			})
			if err != nil {
				t.Fatalf("normalizeWebApplicationInput: %v", err)
			}
		})
	}
}

func TestNewWebApplicationCreateRequestUsesFixedPKCEProfile(t *testing.T) {
	tests := []struct {
		name       string
		refresh    bool
		devMode    bool
		wantGrants []appV2.OIDCGrantType
	}{
		{
			name:       "authorization code only",
			wantGrants: []appV2.OIDCGrantType{appV2.OIDCGrantType_OIDC_GRANT_TYPE_AUTHORIZATION_CODE},
		},
		{
			name:    "refresh enabled",
			refresh: true,
			devMode: true,
			wantGrants: []appV2.OIDCGrantType{
				appV2.OIDCGrantType_OIDC_GRANT_TYPE_AUTHORIZATION_CODE,
				appV2.OIDCGrantType_OIDC_GRANT_TYPE_REFRESH_TOKEN,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			normalized, err := normalizeWebApplicationInput(WebApplicationInput{
				Name:                   "Citius Workbench",
				RedirectURIs:           []string{"https://ui.example.test/auth/callback"},
				PostLogoutRedirectURIs: []string{"https://ui.example.test/"},
				EnableRefreshTokens:    tt.refresh,
				DevMode:                tt.devMode,
			})
			if err != nil {
				t.Fatalf("normalizeWebApplicationInput: %v", err)
			}

			request := newWebApplicationCreateRequest("project-1", normalized)
			oidc := request.GetOidcConfiguration()
			if request.GetProjectId() != "project-1" || request.GetName() != "Citius Workbench" || oidc == nil {
				t.Fatalf("unexpected application request: %+v", request)
			}
			if !reflect.DeepEqual(oidc.GetRedirectUris(), normalized.redirectURIs) || !reflect.DeepEqual(oidc.GetPostLogoutRedirectUris(), normalized.postLogoutRedirectURIs) {
				t.Fatalf("unexpected redirect URI sets: %+v", oidc)
			}
			if !reflect.DeepEqual(oidc.GetResponseTypes(), []appV2.OIDCResponseType{appV2.OIDCResponseType_OIDC_RESPONSE_TYPE_CODE}) {
				t.Fatalf("response types = %v, want Authorization Code", oidc.GetResponseTypes())
			}
			if !reflect.DeepEqual(oidc.GetGrantTypes(), tt.wantGrants) {
				t.Fatalf("grant types = %v, want %v", oidc.GetGrantTypes(), tt.wantGrants)
			}
			if oidc.GetApplicationType() != appV2.OIDCApplicationType_OIDC_APP_TYPE_WEB || oidc.GetAuthMethodType() != appV2.OIDCAuthMethodType_OIDC_AUTH_METHOD_TYPE_NONE {
				t.Fatalf("unexpected public Web client profile: %+v", oidc)
			}
			if oidc.GetVersion() != appV2.OIDCVersion_OIDC_VERSION_1_0 || oidc.GetAccessTokenType() != appV2.OIDCTokenType_OIDC_TOKEN_TYPE_BEARER {
				t.Fatalf("unexpected OIDC/token profile: %+v", oidc)
			}
			if oidc.GetDevelopmentMode() != tt.devMode {
				t.Fatalf("development mode = %v, want %v", oidc.GetDevelopmentMode(), tt.devMode)
			}
			if request.GetApiConfiguration() != nil || request.GetSamlConfiguration() != nil || oidc.GetAccessTokenRoleAssertion() || oidc.GetIdTokenRoleAssertion() || oidc.GetIdTokenUserinfoAssertion() || len(oidc.GetAdditionalOrigins()) != 0 || oidc.GetBackChannelLogoutUri() != "" || oidc.GetClockSkew() != nil || oidc.GetLoginVersion() != nil {
				t.Fatalf("unexpected optional OIDC features: %+v", oidc)
			}
		})
	}
}
