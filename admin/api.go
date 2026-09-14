package admin

import (
	"context"

	appV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/application/v2"
	authzV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/authorization/v2"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
	orgV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/org/v2"
	projV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/project/v2"
	userV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	"google.golang.org/grpc"
)

type organizationService interface {
	ListOrganizations(context.Context, *orgV2.ListOrganizationsRequest, ...grpc.CallOption) (*orgV2.ListOrganizationsResponse, error)
}

type projectService interface {
	CreateProject(context.Context, *projV2.CreateProjectRequest, ...grpc.CallOption) (*projV2.CreateProjectResponse, error)
	ListProjects(context.Context, *projV2.ListProjectsRequest, ...grpc.CallOption) (*projV2.ListProjectsResponse, error)
	AddProjectRole(context.Context, *projV2.AddProjectRoleRequest, ...grpc.CallOption) (*projV2.AddProjectRoleResponse, error)
}

type applicationService interface {
	CreateApplication(context.Context, *appV2.CreateApplicationRequest, ...grpc.CallOption) (*appV2.CreateApplicationResponse, error)
	UpdateApplication(context.Context, *appV2.UpdateApplicationRequest, ...grpc.CallOption) (*appV2.UpdateApplicationResponse, error)
	ListApplications(context.Context, *appV2.ListApplicationsRequest, ...grpc.CallOption) (*appV2.ListApplicationsResponse, error)
}

type userService interface {
	CreateUser(context.Context, *userV2.CreateUserRequest, ...grpc.CallOption) (*userV2.CreateUserResponse, error)
	GetUserByID(context.Context, *userV2.GetUserByIDRequest, ...grpc.CallOption) (*userV2.GetUserByIDResponse, error)
	ListUsers(context.Context, *userV2.ListUsersRequest, ...grpc.CallOption) (*userV2.ListUsersResponse, error)
	DeleteUser(context.Context, *userV2.DeleteUserRequest, ...grpc.CallOption) (*userV2.DeleteUserResponse, error)
	SetPassword(context.Context, *userV2.SetPasswordRequest, ...grpc.CallOption) (*userV2.SetPasswordResponse, error)
	AddSecret(context.Context, *userV2.AddSecretRequest, ...grpc.CallOption) (*userV2.AddSecretResponse, error)
	ListUserMetadata(context.Context, *userV2.ListUserMetadataRequest, ...grpc.CallOption) (*userV2.ListUserMetadataResponse, error)
	SetUserMetadata(context.Context, *userV2.SetUserMetadataRequest, ...grpc.CallOption) (*userV2.SetUserMetadataResponse, error)
	DeleteUserMetadata(context.Context, *userV2.DeleteUserMetadataRequest, ...grpc.CallOption) (*userV2.DeleteUserMetadataResponse, error)
}

type authorizationService interface {
	ListAuthorizations(context.Context, *authzV2.ListAuthorizationsRequest, ...grpc.CallOption) (*authzV2.ListAuthorizationsResponse, error)
	CreateAuthorization(context.Context, *authzV2.CreateAuthorizationRequest, ...grpc.CallOption) (*authzV2.CreateAuthorizationResponse, error)
	DeleteAuthorization(context.Context, *authzV2.DeleteAuthorizationRequest, ...grpc.CallOption) (*authzV2.DeleteAuthorizationResponse, error)
}

type managementService interface {
	UpdateOIDCAppConfig(context.Context, *management.UpdateOIDCAppConfigRequest, ...grpc.CallOption) (*management.UpdateOIDCAppConfigResponse, error)
	ListActions(context.Context, *management.ListActionsRequest, ...grpc.CallOption) (*management.ListActionsResponse, error)
	CreateAction(context.Context, *management.CreateActionRequest, ...grpc.CallOption) (*management.CreateActionResponse, error)
	UpdateAction(context.Context, *management.UpdateActionRequest, ...grpc.CallOption) (*management.UpdateActionResponse, error)
	GetFlow(context.Context, *management.GetFlowRequest, ...grpc.CallOption) (*management.GetFlowResponse, error)
	SetTriggerActions(context.Context, *management.SetTriggerActionsRequest, ...grpc.CallOption) (*management.SetTriggerActionsResponse, error)
}

type adminServices struct {
	organizations  organizationService
	projects       projectService
	applications   applicationService
	users          userService
	authorizations authorizationService
	management     managementService
	close          func() error
}
