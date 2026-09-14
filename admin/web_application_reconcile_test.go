package admin

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	appV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/application/v2"
	projV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/project/v2"
	"google.golang.org/grpc"
)

type webApplicationServiceFake struct {
	applicationService
	list   func(context.Context, *appV2.ListApplicationsRequest) (*appV2.ListApplicationsResponse, error)
	create func(context.Context, *appV2.CreateApplicationRequest) (*appV2.CreateApplicationResponse, error)
	update func(context.Context, *appV2.UpdateApplicationRequest) (*appV2.UpdateApplicationResponse, error)
}

func (f *webApplicationServiceFake) ListApplications(ctx context.Context, in *appV2.ListApplicationsRequest, _ ...grpc.CallOption) (*appV2.ListApplicationsResponse, error) {
	return f.list(ctx, in)
}

func (f *webApplicationServiceFake) CreateApplication(ctx context.Context, in *appV2.CreateApplicationRequest, _ ...grpc.CallOption) (*appV2.CreateApplicationResponse, error) {
	return f.create(ctx, in)
}

func (f *webApplicationServiceFake) UpdateApplication(ctx context.Context, in *appV2.UpdateApplicationRequest, _ ...grpc.CallOption) (*appV2.UpdateApplicationResponse, error) {
	return f.update(ctx, in)
}

type webProjectServiceFake struct {
	projectService
}

func (f *webProjectServiceFake) ListProjects(context.Context, *projV2.ListProjectsRequest, ...grpc.CallOption) (*projV2.ListProjectsResponse, error) {
	return &projV2.ListProjectsResponse{Projects: []*projV2.Project{{ProjectId: "project-1", OrganizationId: "org-1", Name: "citius"}}}, nil
}

func TestEnsureWebApplicationCreatesMissingApplication(t *testing.T) {
	var createRequest *appV2.CreateApplicationRequest
	var logs bytes.Buffer
	applications := &webApplicationServiceFake{
		list: func(context.Context, *appV2.ListApplicationsRequest) (*appV2.ListApplicationsResponse, error) {
			return applicationLookupResponse(0), nil
		},
		create: func(_ context.Context, in *appV2.CreateApplicationRequest) (*appV2.CreateApplicationResponse, error) {
			createRequest = in
			return &appV2.CreateApplicationResponse{
				ApplicationId: "app-1",
				ApplicationType: &appV2.CreateApplicationResponse_OidcConfiguration{
					OidcConfiguration: &appV2.CreateOIDCApplicationResponse{ClientId: "client-1", ClientSecret: "must-not-leak"},
				},
			}, nil
		},
		update: func(context.Context, *appV2.UpdateApplicationRequest) (*appV2.UpdateApplicationResponse, error) {
			t.Fatal("UpdateApplication must not be called when creating")
			return nil, nil
		},
	}
	client := newWebApplicationTestClient(applications, slog.New(slog.NewTextHandler(&logs, nil)))

	result, err := client.EnsureWebApplication(context.Background(), validWebApplicationInput())
	if err != nil {
		t.Fatalf("EnsureWebApplication: %v", err)
	}
	if result.ApplicationID != "app-1" || result.ClientID != "client-1" || !result.Created || result.Updated {
		t.Fatalf("result = %+v, want created app-1/client-1", result)
	}
	if createRequest == nil || createRequest.GetProjectId() != "project-1" || createRequest.GetOidcConfiguration() == nil {
		t.Fatalf("unexpected create request: %+v", createRequest)
	}
	if strings.Contains(logs.String(), "must-not-leak") {
		t.Fatalf("log contains client secret: %s", logs.String())
	}
}

func TestEnsureWebApplicationLeavesEquivalentApplicationUnchanged(t *testing.T) {
	in := validWebApplicationInput()
	in.RedirectURIs[0], in.RedirectURIs[1] = in.RedirectURIs[1], in.RedirectURIs[0]
	existing := matchingWebApplication(t, in)
	existing.GetOidcConfiguration().RedirectUris[0], existing.GetOidcConfiguration().RedirectUris[1] = existing.GetOidcConfiguration().RedirectUris[1], existing.GetOidcConfiguration().RedirectUris[0]
	existing.GetOidcConfiguration().GrantTypes[0], existing.GetOidcConfiguration().GrantTypes[1] = existing.GetOidcConfiguration().GrantTypes[1], existing.GetOidcConfiguration().GrantTypes[0]
	applications := &webApplicationServiceFake{
		list: func(context.Context, *appV2.ListApplicationsRequest) (*appV2.ListApplicationsResponse, error) {
			return applicationLookupResponse(1, existing), nil
		},
		create: func(context.Context, *appV2.CreateApplicationRequest) (*appV2.CreateApplicationResponse, error) {
			t.Fatal("CreateApplication must not be called for an existing application")
			return nil, nil
		},
		update: func(context.Context, *appV2.UpdateApplicationRequest) (*appV2.UpdateApplicationResponse, error) {
			t.Fatal("UpdateApplication must not be called for equivalent reordered settings")
			return nil, nil
		},
	}
	client := newWebApplicationTestClient(applications, slog.New(slog.NewTextHandler(io.Discard, nil)))

	result, err := client.EnsureWebApplication(context.Background(), in)
	if err != nil {
		t.Fatalf("EnsureWebApplication: %v", err)
	}
	if result.ApplicationID != "app-1" || result.ClientID != "client-1" || result.Created || result.Updated {
		t.Fatalf("result = %+v, want unchanged app-1/client-1", result)
	}
}

func TestEnsureWebApplicationReconcilesDrift(t *testing.T) {
	in := validWebApplicationInput()
	var updateRequest *appV2.UpdateApplicationRequest
	existing := matchingWebApplication(t, in)
	existing.Configuration = &appV2.Application_OidcConfiguration{OidcConfiguration: &appV2.OIDCConfiguration{
		ClientId:                 "client-1",
		RedirectUris:             []string{"https://ui.example.test/obsolete"},
		ResponseTypes:            []appV2.OIDCResponseType{appV2.OIDCResponseType_OIDC_RESPONSE_TYPE_ID_TOKEN},
		GrantTypes:               []appV2.OIDCGrantType{appV2.OIDCGrantType_OIDC_GRANT_TYPE_IMPLICIT},
		ApplicationType:          appV2.OIDCApplicationType_OIDC_APP_TYPE_NATIVE,
		AuthMethodType:           appV2.OIDCAuthMethodType_OIDC_AUTH_METHOD_TYPE_BASIC,
		PostLogoutRedirectUris:   []string{"https://ui.example.test/signed-out", "https://ui.example.test/obsolete"},
		DevelopmentMode:          true,
		AccessTokenType:          appV2.OIDCTokenType_OIDC_TOKEN_TYPE_JWT,
		AccessTokenRoleAssertion: true,
		IdTokenRoleAssertion:     true,
		IdTokenUserinfoAssertion: true,
	}}
	applications := &webApplicationServiceFake{
		list: func(context.Context, *appV2.ListApplicationsRequest) (*appV2.ListApplicationsResponse, error) {
			return applicationLookupResponse(1, existing), nil
		},
		create: func(context.Context, *appV2.CreateApplicationRequest) (*appV2.CreateApplicationResponse, error) {
			t.Fatal("CreateApplication must not be called while reconciling")
			return nil, nil
		},
		update: func(_ context.Context, in *appV2.UpdateApplicationRequest) (*appV2.UpdateApplicationResponse, error) {
			updateRequest = in
			return &appV2.UpdateApplicationResponse{}, nil
		},
	}
	client := newWebApplicationTestClient(applications, slog.New(slog.NewTextHandler(io.Discard, nil)))

	result, err := client.EnsureWebApplication(context.Background(), in)
	if err != nil {
		t.Fatalf("EnsureWebApplication: %v", err)
	}
	if result.ApplicationID != "app-1" || result.ClientID != "client-1" || result.Created || !result.Updated {
		t.Fatalf("result = %+v, want updated app-1/client-1", result)
	}
	assertWebApplicationUpdateRequest(t, updateRequest, in)
}

func TestEnsureWebApplicationRejectsTypeCollision(t *testing.T) {
	tests := []struct {
		name        string
		application *appV2.Application
	}{
		{
			name: "API",
			application: &appV2.Application{
				ApplicationId: "app-1",
				ProjectId:     "project-1",
				Name:          "Citius Workbench",
				Configuration: &appV2.Application_ApiConfiguration{ApiConfiguration: &appV2.APIConfiguration{}},
			},
		},
		{
			name: "SAML",
			application: &appV2.Application{
				ApplicationId: "app-1",
				ProjectId:     "project-1",
				Name:          "Citius Workbench",
				Configuration: &appV2.Application_SamlConfiguration{SamlConfiguration: &appV2.SAMLConfiguration{}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			applications := &webApplicationServiceFake{
				list: func(context.Context, *appV2.ListApplicationsRequest) (*appV2.ListApplicationsResponse, error) {
					return applicationLookupResponse(1, tt.application), nil
				},
				create: func(context.Context, *appV2.CreateApplicationRequest) (*appV2.CreateApplicationResponse, error) {
					t.Fatal("CreateApplication must not be called for a type collision")
					return nil, nil
				},
				update: func(context.Context, *appV2.UpdateApplicationRequest) (*appV2.UpdateApplicationResponse, error) {
					t.Fatal("UpdateApplication must not be called for a type collision")
					return nil, nil
				},
			}
			client := newWebApplicationTestClient(applications, slog.New(slog.NewTextHandler(io.Discard, nil)))

			result, err := client.EnsureWebApplication(context.Background(), validWebApplicationInput())
			if result != nil || !errors.Is(err, ErrApplicationTypeMismatch) {
				t.Fatalf("EnsureWebApplication type collision = (%v, %v), want (nil, ErrApplicationTypeMismatch)", result, err)
			}
		})
	}
}

func newWebApplicationTestClient(applications applicationService, logger *slog.Logger) *Client {
	return &Client{
		api: adminServices{
			projects:     &webProjectServiceFake{},
			applications: applications,
		},
		cfg:    Config{OrgID: "org-1", ProjectID: "project-1"},
		logger: logger,
	}
}

func validWebApplicationInput() WebApplicationInput {
	return WebApplicationInput{
		Name: "Citius Workbench",
		RedirectURIs: []string{
			"https://ui.example.test/auth/callback",
			"https://ui.example.test/auth/secondary",
		},
		PostLogoutRedirectURIs: []string{"https://ui.example.test/signed-out"},
		EnableRefreshTokens:    true,
	}
}

func matchingWebApplication(t *testing.T, in WebApplicationInput) *appV2.Application {
	t.Helper()
	normalized, err := normalizeWebApplicationInput(in)
	if err != nil {
		t.Fatalf("normalizeWebApplicationInput: %v", err)
	}
	request := newWebApplicationCreateRequest("project-1", normalized).GetOidcConfiguration()
	return &appV2.Application{
		ApplicationId: "app-1",
		ProjectId:     "project-1",
		Name:          normalized.name,
		Configuration: &appV2.Application_OidcConfiguration{OidcConfiguration: &appV2.OIDCConfiguration{
			ClientId:                 "client-1",
			RedirectUris:             request.GetRedirectUris(),
			ResponseTypes:            request.GetResponseTypes(),
			GrantTypes:               request.GetGrantTypes(),
			ApplicationType:          request.GetApplicationType(),
			AuthMethodType:           request.GetAuthMethodType(),
			PostLogoutRedirectUris:   request.GetPostLogoutRedirectUris(),
			Version:                  request.GetVersion(),
			DevelopmentMode:          request.GetDevelopmentMode(),
			AccessTokenType:          request.GetAccessTokenType(),
			AccessTokenRoleAssertion: request.GetAccessTokenRoleAssertion(),
			IdTokenRoleAssertion:     request.GetIdTokenRoleAssertion(),
			IdTokenUserinfoAssertion: request.GetIdTokenUserinfoAssertion(),
		}},
	}
}

func assertWebApplicationUpdateRequest(t *testing.T, request *appV2.UpdateApplicationRequest, in WebApplicationInput) {
	t.Helper()
	if request == nil || request.GetApplicationId() != "app-1" || request.GetProjectId() != "project-1" || request.GetName() != "Citius Workbench" {
		t.Fatalf("unexpected update identity: %+v", request)
	}
	normalized, err := normalizeWebApplicationInput(in)
	if err != nil {
		t.Fatalf("normalizeWebApplicationInput: %v", err)
	}
	oidc := request.GetOidcConfiguration()
	if oidc == nil || !reflect.DeepEqual(oidc.GetRedirectUris(), normalized.redirectURIs) || !reflect.DeepEqual(oidc.GetPostLogoutRedirectUris(), normalized.postLogoutRedirectURIs) {
		t.Fatalf("unexpected update URI sets: %+v", oidc)
	}
	if !reflect.DeepEqual(oidc.GetResponseTypes(), []appV2.OIDCResponseType{appV2.OIDCResponseType_OIDC_RESPONSE_TYPE_CODE}) || !reflect.DeepEqual(oidc.GetGrantTypes(), webApplicationGrantTypes(true)) {
		t.Fatalf("unexpected update flow: %+v", oidc)
	}
	if oidc.GetApplicationType() != appV2.OIDCApplicationType_OIDC_APP_TYPE_WEB || oidc.GetAuthMethodType() != appV2.OIDCAuthMethodType_OIDC_AUTH_METHOD_TYPE_NONE || oidc.GetVersion() != appV2.OIDCVersion_OIDC_VERSION_1_0 || oidc.GetAccessTokenType() != appV2.OIDCTokenType_OIDC_TOKEN_TYPE_BEARER {
		t.Fatalf("unexpected update security profile: %+v", oidc)
	}
	if oidc.ApplicationType == nil || oidc.AuthMethodType == nil || oidc.Version == nil || oidc.DevelopmentMode == nil || oidc.AccessTokenType == nil || oidc.AccessTokenRoleAssertion == nil || oidc.IdTokenRoleAssertion == nil || oidc.IdTokenUserinfoAssertion == nil {
		t.Fatal("update must explicitly own every security-profile field")
	}
	if oidc.GetDevelopmentMode() || oidc.GetAccessTokenRoleAssertion() || oidc.GetIdTokenRoleAssertion() || oidc.GetIdTokenUserinfoAssertion() {
		t.Fatalf("unexpected enabled update option: %+v", oidc)
	}
}
