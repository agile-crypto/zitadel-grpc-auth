package admin

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	actionV1 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/action"
	appV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/application/v2"
	authzV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/authorization/v2"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
	metadataV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/metadata/v2"
	projV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/project/v2"
	userV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"
)

type verifyProjectService struct {
	projectService
	t       *testing.T
	project *projV2.Project
}

func (f *verifyProjectService) ListProjects(context.Context, *projV2.ListProjectsRequest, ...grpc.CallOption) (*projV2.ListProjectsResponse, error) {
	return &projV2.ListProjectsResponse{Projects: []*projV2.Project{f.project}}, nil
}

func (f *verifyProjectService) CreateProject(context.Context, *projV2.CreateProjectRequest, ...grpc.CallOption) (*projV2.CreateProjectResponse, error) {
	f.t.Fatal("verification must not create projects")
	return nil, nil
}

func (f *verifyProjectService) AddProjectRole(context.Context, *projV2.AddProjectRoleRequest, ...grpc.CallOption) (*projV2.AddProjectRoleResponse, error) {
	f.t.Fatal("verification must not add project roles")
	return nil, nil
}

type verifyApplicationService struct {
	applicationService
	t           *testing.T
	application *appV2.Application
}

func (f *verifyApplicationService) ListApplications(context.Context, *appV2.ListApplicationsRequest, ...grpc.CallOption) (*appV2.ListApplicationsResponse, error) {
	if f.application == nil {
		return applicationLookupResponse(0), nil
	}
	return applicationLookupResponse(1, f.application), nil
}

func (f *verifyApplicationService) CreateApplication(context.Context, *appV2.CreateApplicationRequest, ...grpc.CallOption) (*appV2.CreateApplicationResponse, error) {
	f.t.Fatal("verification must not create applications")
	return nil, nil
}

func (f *verifyApplicationService) UpdateApplication(context.Context, *appV2.UpdateApplicationRequest, ...grpc.CallOption) (*appV2.UpdateApplicationResponse, error) {
	f.t.Fatal("verification must not update applications")
	return nil, nil
}

type verifyUserService struct {
	userService
	t        *testing.T
	users    []*userV2.User
	metadata map[string][]*metadataV2.Metadata
}

func (f *verifyUserService) ListUsers(context.Context, *userV2.ListUsersRequest, ...grpc.CallOption) (*userV2.ListUsersResponse, error) {
	return &userV2.ListUsersResponse{Result: f.users}, nil
}

func (f *verifyUserService) ListUserMetadata(_ context.Context, in *userV2.ListUserMetadataRequest, _ ...grpc.CallOption) (*userV2.ListUserMetadataResponse, error) {
	return &userV2.ListUserMetadataResponse{Metadata: f.metadata[in.GetUserId()]}, nil
}

func (f *verifyUserService) CreateUser(context.Context, *userV2.CreateUserRequest, ...grpc.CallOption) (*userV2.CreateUserResponse, error) {
	f.t.Fatal("verification must not create users")
	return nil, nil
}

func (f *verifyUserService) DeleteUser(context.Context, *userV2.DeleteUserRequest, ...grpc.CallOption) (*userV2.DeleteUserResponse, error) {
	f.t.Fatal("verification must not delete users")
	return nil, nil
}

func (f *verifyUserService) SetPassword(context.Context, *userV2.SetPasswordRequest, ...grpc.CallOption) (*userV2.SetPasswordResponse, error) {
	f.t.Fatal("verification must not set passwords")
	return nil, nil
}

func (f *verifyUserService) AddSecret(context.Context, *userV2.AddSecretRequest, ...grpc.CallOption) (*userV2.AddSecretResponse, error) {
	f.t.Fatal("verification must not mint secrets")
	return nil, nil
}

func (f *verifyUserService) SetUserMetadata(context.Context, *userV2.SetUserMetadataRequest, ...grpc.CallOption) (*userV2.SetUserMetadataResponse, error) {
	f.t.Fatal("verification must not set metadata")
	return nil, nil
}

func (f *verifyUserService) DeleteUserMetadata(context.Context, *userV2.DeleteUserMetadataRequest, ...grpc.CallOption) (*userV2.DeleteUserMetadataResponse, error) {
	f.t.Fatal("verification must not delete metadata")
	return nil, nil
}

type verifyAuthorizationService struct {
	authorizationService
	t              *testing.T
	authorizations []*authzV2.Authorization
}

func (f *verifyAuthorizationService) ListAuthorizations(context.Context, *authzV2.ListAuthorizationsRequest, ...grpc.CallOption) (*authzV2.ListAuthorizationsResponse, error) {
	return &authzV2.ListAuthorizationsResponse{Authorizations: f.authorizations}, nil
}

func (f *verifyAuthorizationService) CreateAuthorization(context.Context, *authzV2.CreateAuthorizationRequest, ...grpc.CallOption) (*authzV2.CreateAuthorizationResponse, error) {
	f.t.Fatal("verification must not create authorizations")
	return nil, nil
}

func (f *verifyAuthorizationService) DeleteAuthorization(context.Context, *authzV2.DeleteAuthorizationRequest, ...grpc.CallOption) (*authzV2.DeleteAuthorizationResponse, error) {
	f.t.Fatal("verification must not delete authorizations")
	return nil, nil
}

type verifyManagementService struct {
	managementService
	t      *testing.T
	action *actionV1.Action
	wired  bool
}

func (f *verifyManagementService) ListActions(context.Context, *management.ListActionsRequest, ...grpc.CallOption) (*management.ListActionsResponse, error) {
	if f.action == nil {
		return &management.ListActionsResponse{}, nil
	}
	return &management.ListActionsResponse{Result: []*actionV1.Action{f.action}}, nil
}

func (f *verifyManagementService) GetFlow(context.Context, *management.GetFlowRequest, ...grpc.CallOption) (*management.GetFlowResponse, error) {
	var actions []*actionV1.Action
	if f.wired && f.action != nil {
		actions = []*actionV1.Action{{Id: f.action.GetId()}}
	}
	return &management.GetFlowResponse{Flow: &actionV1.Flow{TriggerActions: []*actionV1.TriggerAction{{
		TriggerType: &actionV1.TriggerType{Id: humanTokenTriggerType},
		Actions:     actions,
	}}}}, nil
}

func (f *verifyManagementService) CreateAction(context.Context, *management.CreateActionRequest, ...grpc.CallOption) (*management.CreateActionResponse, error) {
	f.t.Fatal("verification must not create actions")
	return nil, nil
}

func (f *verifyManagementService) UpdateAction(context.Context, *management.UpdateActionRequest, ...grpc.CallOption) (*management.UpdateActionResponse, error) {
	f.t.Fatal("verification must not update actions")
	return nil, nil
}

func (f *verifyManagementService) SetTriggerActions(context.Context, *management.SetTriggerActionsRequest, ...grpc.CallOption) (*management.SetTriggerActionsResponse, error) {
	f.t.Fatal("verification must not wire actions")
	return nil, nil
}

func TestVerifyHumanAuthConfigurationReportsCurrentConfiguration(t *testing.T) {
	client, input := newVerificationFixture(t)

	result, err := client.VerifyHumanAuthConfiguration(context.Background(), input)
	if err != nil {
		t.Fatalf("VerifyHumanAuthConfiguration: %v", err)
	}
	if !result.Current || len(result.Drift) != 0 || result.ProjectID != "project-1" {
		t.Fatalf("result = %+v, want current project-1 configuration", result)
	}
}

func TestVerifyHumanAuthConfigurationReportsStructuredDriftWithoutSecrets(t *testing.T) {
	client, input := newVerificationFixture(t)
	projects := client.api.projects.(*verifyProjectService)
	projects.project.ProjectRoleAssertion = false
	applications := client.api.applications.(*verifyApplicationService)
	oidc := applications.application.GetOidcConfiguration()
	oidc.RedirectUris = []string{"https://obsolete.example.test/callback"}
	oidc.AuthMethodType = appV2.OIDCAuthMethodType_OIDC_AUTH_METHOD_TYPE_BASIC
	users := client.api.users.(*verifyUserService)
	human := users.users[0].GetHuman()
	users.users[0].State = userV2.UserState_USER_STATE_LOCKED
	human.Profile.GivenName = "Wrong"
	human.Email.IsVerified = false
	human.PasswordChangeRequired = false
	users.metadata["human-1"][0].Value = []byte("super-secret")
	authorizations := client.api.authorizations.(*verifyAuthorizationService)
	authorizations.authorizations[0].Roles = []*authzV2.Role{{Key: "decrypt"}}
	authorizations.authorizations[0].State = authzV2.State_STATE_INACTIVE
	managementService := client.api.management.(*verifyManagementService)
	managementService.action.Script = "wrong script"
	managementService.wired = false

	result, err := client.VerifyHumanAuthConfiguration(context.Background(), input)
	if err != nil {
		t.Fatalf("VerifyHumanAuthConfiguration: %v", err)
	}
	if result.Current {
		t.Fatalf("result = %+v, want drift", result)
	}
	fields := make(map[string]bool, len(result.Drift))
	for _, drift := range result.Drift {
		fields[drift.Field] = true
	}
	for _, field := range []string{
		"project_role_assertion",
		"script",
		"token_flow_trigger",
		"redirect_uris",
		"auth_method_type",
		"state",
		"profile.given_name",
		"email.verified",
		"password_change_required",
		"authorization.state",
		"roles",
		"metadata.urn:citius:key_access",
	} {
		if !fields[field] {
			t.Errorf("drift fields = %v, missing %q", fields, field)
		}
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal result: %v", err)
	}
	if strings.Contains(string(encoded), "super-secret") {
		t.Fatalf("verification result leaked unrelated metadata: %s", encoded)
	}
}

func TestVerifyHumanAuthConfigurationReportsMissingResources(t *testing.T) {
	client, input := newVerificationFixture(t)
	client.api.applications.(*verifyApplicationService).application = nil
	client.api.users.(*verifyUserService).users = nil
	client.api.management.(*verifyManagementService).action = nil
	client.api.authorizations.(*verifyAuthorizationService).authorizations = nil

	result, err := client.VerifyHumanAuthConfiguration(context.Background(), input)
	if err != nil {
		t.Fatalf("VerifyHumanAuthConfiguration: %v", err)
	}
	if result.Current {
		t.Fatalf("result = %+v, want missing-resource drift", result)
	}
	wantResources := map[string]bool{
		"action/injectUrnCitiusClaims": false,
		"application/Citius Workbench": false,
		"human/producer":               false,
	}
	for _, drift := range result.Drift {
		if drift.Field == "exists" {
			if _, expected := wantResources[drift.Resource]; expected {
				wantResources[drift.Resource] = true
			}
		}
	}
	for resource, found := range wantResources {
		if !found {
			t.Errorf("drift = %+v, missing existence drift for %s", result.Drift, resource)
		}
	}
}

func TestVerifyHumanAuthConfigurationReportsResourceTypeCollisions(t *testing.T) {
	client, input := newVerificationFixture(t)
	client.api.applications.(*verifyApplicationService).application.Configuration = &appV2.Application_ApiConfiguration{
		ApiConfiguration: &appV2.APIConfiguration{},
	}
	client.api.users.(*verifyUserService).users[0].Type = &userV2.User_Machine{
		Machine: &userV2.MachineUser{},
	}

	result, err := client.VerifyHumanAuthConfiguration(context.Background(), input)
	if err != nil {
		t.Fatalf("VerifyHumanAuthConfiguration: %v", err)
	}
	types := make(map[string]ConfigurationDrift)
	for _, drift := range result.Drift {
		if drift.Field == "type" {
			types[drift.Resource] = drift
		}
	}
	if types["application/Citius Workbench"].Actual != "API" || types["human/producer"].Actual != "machine" {
		t.Fatalf("type drift = %+v, want API application and machine user collisions", types)
	}
}

func TestValidateHumanConfigurationsRejectsDuplicateUsers(t *testing.T) {
	human := validHumanConfiguration()
	err := validateHumanConfigurations([]HumanConfiguration{human, human})
	if err == nil || !strings.Contains(err.Error(), "duplicate human Username") {
		t.Fatalf("validateHumanConfigurations error = %v, want duplicate username", err)
	}
}

func newVerificationFixture(t *testing.T) (*Client, HumanAuthConfigurationInput) {
	t.Helper()
	web := validWebApplicationInput()
	actionScript, err := RenderActionScript("urn:citius")
	if err != nil {
		t.Fatalf("RenderActionScript: %v", err)
	}
	human := validHumanConfiguration()
	keyMetadata, err := marshalKeyAccess(human.KeyAccess)
	if err != nil {
		t.Fatalf("marshalKeyAccess: %v", err)
	}
	policyMetadata, err := marshalPolicyAccess(human.PolicyAccess)
	if err != nil {
		t.Fatalf("marshalPolicyAccess: %v", err)
	}
	user := &userV2.User{
		UserId:   "human-1",
		State:    userV2.UserState_USER_STATE_ACTIVE,
		Username: human.Username,
		Type: &userV2.User_Human{Human: &userV2.HumanUser{
			UserId:   "human-1",
			Username: human.Username,
			State:    userV2.UserState_USER_STATE_ACTIVE,
			Profile: &userV2.HumanProfile{
				GivenName:   human.GivenName,
				FamilyName:  human.FamilyName,
				DisplayName: strPtr(human.DisplayName),
			},
			Email:                  &userV2.HumanEmail{Email: human.Email, IsVerified: human.EmailVerified},
			PasswordChangeRequired: human.PasswordChangeRequired,
		}},
	}
	action := &actionV1.Action{
		Id:            "action-1",
		Name:          actionNameForNamespace("urn:citius"),
		State:         actionV1.ActionState_ACTION_STATE_ACTIVE,
		Script:        actionScript,
		Timeout:       durationpb.New(10 * time.Second),
		AllowedToFail: false,
	}
	return &Client{
			api: adminServices{
				projects: &verifyProjectService{t: t, project: &projV2.Project{
					ProjectId: "project-1", OrganizationId: "org-1", Name: "citius", ProjectRoleAssertion: true,
				}},
				applications: &verifyApplicationService{t: t, application: matchingWebApplication(t, web)},
				users: &verifyUserService{t: t, users: []*userV2.User{user}, metadata: map[string][]*metadataV2.Metadata{
					"human-1": {
						{Key: keyAccessMetadataKey("urn:citius"), Value: keyMetadata},
						{Key: policyAccessMetadataKey("urn:citius"), Value: policyMetadata},
					},
				}},
				authorizations: &verifyAuthorizationService{t: t, authorizations: []*authzV2.Authorization{{
					Id:      "authorization-1",
					Project: &authzV2.Project{Id: "project-1"},
					User:    &authzV2.User{Id: "human-1"},
					State:   authzV2.State_STATE_ACTIVE,
					Roles:   []*authzV2.Role{{Key: "encrypt"}, {Key: "sign"}},
				}}},
				management: &verifyManagementService{t: t, action: action, wired: true},
			},
			cfg: Config{OrgID: "org-1", ProjectID: "project-1", Namespace: "urn:citius"},
		}, HumanAuthConfigurationInput{
			ClaimNamespace: "urn:citius",
			Humans:         []HumanConfiguration{human},
			WebApplication: web,
		}
}

func validHumanConfiguration() HumanConfiguration {
	return HumanConfiguration{
		Username:               "producer",
		GivenName:              "Demo",
		FamilyName:             "Producer",
		DisplayName:            "Demo Producer",
		Email:                  "producer@example.test",
		EmailVerified:          true,
		PasswordChangeRequired: true,
		Permissions:            []string{"sign", "encrypt"},
		KeyAccess: KeyAccess{
			AllowedKeyPatterns: []string{"producer-*"},
			DenyKeyPatterns:    []string{"producer-prod-*"},
		},
		PolicyAccess: PolicyAccess{
			AllowedPolicyPatterns: []string{"default-*"},
			DenyPolicyPatterns:    []string{"restricted-*"},
		},
	}
}
