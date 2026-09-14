package admin

import (
	"context"
	"errors"
	"testing"

	appV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/application/v2"
	filterV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/filter/v2"
	objectV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/object/v2"
	userV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	"google.golang.org/grpc"
)

type fakeApplicationService struct {
	applicationService
	listApplications func(context.Context, *appV2.ListApplicationsRequest) (*appV2.ListApplicationsResponse, error)
}

func (f *fakeApplicationService) ListApplications(ctx context.Context, in *appV2.ListApplicationsRequest, _ ...grpc.CallOption) (*appV2.ListApplicationsResponse, error) {
	return f.listApplications(ctx, in)
}

func TestLookupUserByUsernameUsesExactScopedFiltersAndPagination(t *testing.T) {
	var offsets []uint64
	users := &fakeUserService{
		listUsers: func(_ context.Context, in *userV2.ListUsersRequest) (*userV2.ListUsersResponse, error) {
			offsets = append(offsets, in.GetQuery().GetOffset())
			assertUserLookupFilters(t, in, "org-1", "producer")
			if in.GetQuery().GetOffset() == 0 {
				return userLookupResponse(2, &userV2.User{Username: "producer-extra"}), nil
			}
			return userLookupResponse(2, &userV2.User{UserId: "user-2", Username: "producer"}), nil
		},
	}
	client := &Client{api: adminServices{users: users}}

	got, err := client.lookupUserByUsername(context.Background(), "org-1", " producer ")
	if err != nil {
		t.Fatalf("lookupUserByUsername: %v", err)
	}
	if got.GetUserId() != "user-2" {
		t.Fatalf("lookupUserByUsername user ID = %q, want user-2", got.GetUserId())
	}
	if len(offsets) != 2 || offsets[0] != 0 || offsets[1] != 1 {
		t.Fatalf("lookup offsets = %v, want [0 1]", offsets)
	}
}

func TestLookupUserByUsernameRejectsDuplicateExactMatches(t *testing.T) {
	users := &fakeUserService{
		listUsers: func(_ context.Context, in *userV2.ListUsersRequest) (*userV2.ListUsersResponse, error) {
			return userLookupResponse(2,
				&userV2.User{UserId: "user-1", Username: "producer"},
				&userV2.User{UserId: "user-2", Username: "producer"},
			), nil
		},
	}
	client := &Client{api: adminServices{users: users}}

	got, err := client.lookupUserByUsername(context.Background(), "org-1", "producer")
	if got != nil || !errors.Is(err, ErrAmbiguousResource) {
		t.Fatalf("lookupUserByUsername duplicate = (%v, %v), want (nil, ErrAmbiguousResource)", got, err)
	}
}

func TestEnsureMachineUserRejectsTypeCollision(t *testing.T) {
	users := &fakeUserService{
		listUsers: func(context.Context, *userV2.ListUsersRequest) (*userV2.ListUsersResponse, error) {
			return userLookupResponse(1, &userV2.User{
				UserId:   "human-1",
				Username: "worker",
				Type:     &userV2.User_Human{Human: &userV2.HumanUser{}},
			}), nil
		},
	}
	client := &Client{api: adminServices{users: users}}

	got, created, err := client.ensureMachineUser(context.Background(), "org-1", OnboardInput{Username: "worker"})
	if got != nil || created || !errors.Is(err, ErrUserTypeMismatch) {
		t.Fatalf("ensureMachineUser type collision = (%v, %v, %v), want (nil, false, ErrUserTypeMismatch)", got, created, err)
	}
}

func TestLookupApplicationByNameUsesExactScopedFiltersAndPagination(t *testing.T) {
	var offsets []uint64
	applications := &fakeApplicationService{
		listApplications: func(_ context.Context, in *appV2.ListApplicationsRequest) (*appV2.ListApplicationsResponse, error) {
			offsets = append(offsets, in.GetPagination().GetOffset())
			assertApplicationLookupFilters(t, in, "project-1", "citius-api")
			if in.GetPagination().GetOffset() == 0 {
				return applicationLookupResponse(2, &appV2.Application{ProjectId: "project-1", Name: "citius-api-extra"}), nil
			}
			return applicationLookupResponse(2, &appV2.Application{ApplicationId: "app-2", ProjectId: "project-1", Name: "citius-api"}), nil
		},
	}
	client := &Client{api: adminServices{applications: applications}}

	got, err := client.lookupApplicationByName(context.Background(), "project-1", " citius-api ")
	if err != nil {
		t.Fatalf("lookupApplicationByName: %v", err)
	}
	if got.GetApplicationId() != "app-2" {
		t.Fatalf("lookupApplicationByName application ID = %q, want app-2", got.GetApplicationId())
	}
	if len(offsets) != 2 || offsets[0] != 0 || offsets[1] != 1 {
		t.Fatalf("lookup offsets = %v, want [0 1]", offsets)
	}
}

func TestLookupApplicationByNameRejectsDuplicateExactMatches(t *testing.T) {
	applications := &fakeApplicationService{
		listApplications: func(context.Context, *appV2.ListApplicationsRequest) (*appV2.ListApplicationsResponse, error) {
			return applicationLookupResponse(2,
				&appV2.Application{ApplicationId: "app-1", ProjectId: "project-1", Name: "citius-api"},
				&appV2.Application{ApplicationId: "app-2", ProjectId: "project-1", Name: "citius-api"},
			), nil
		},
	}
	client := &Client{api: adminServices{applications: applications}}

	got, err := client.lookupApplicationByName(context.Background(), "project-1", "citius-api")
	if got != nil || !errors.Is(err, ErrAmbiguousResource) {
		t.Fatalf("lookupApplicationByName duplicate = (%v, %v), want (nil, ErrAmbiguousResource)", got, err)
	}
}

func TestEnsureAPIApplicationRejectsTypeCollision(t *testing.T) {
	applications := &fakeApplicationService{
		listApplications: func(context.Context, *appV2.ListApplicationsRequest) (*appV2.ListApplicationsResponse, error) {
			return applicationLookupResponse(1, &appV2.Application{
				ApplicationId: "oidc-1",
				ProjectId:     "project-1",
				Name:          "citius-api",
				Configuration: &appV2.Application_OidcConfiguration{OidcConfiguration: &appV2.OIDCConfiguration{}},
			}), nil
		},
	}
	client := &Client{api: adminServices{applications: applications}}

	_, err := client.ensureAPIApplication(context.Background(), "project-1", "citius-api")
	if !errors.Is(err, ErrApplicationTypeMismatch) {
		t.Fatalf("ensureAPIApplication type collision error = %v, want ErrApplicationTypeMismatch", err)
	}
}

func assertUserLookupFilters(t *testing.T, request *userV2.ListUsersRequest, orgID, username string) {
	t.Helper()
	if request.GetQuery().GetLimit() != lookupPageSize || !request.GetQuery().GetAsc() {
		t.Fatalf("user pagination = %+v, want limit %d ascending", request.GetQuery(), lookupPageSize)
	}
	if len(request.GetQueries()) != 2 {
		t.Fatalf("user query count = %d, want 2", len(request.GetQueries()))
	}
	usernameQuery := request.GetQueries()[0].GetUserNameQuery()
	if usernameQuery.GetUserName() != username || usernameQuery.GetMethod() != objectV2.TextQueryMethod_TEXT_QUERY_METHOD_EQUALS {
		t.Fatalf("username query = %+v, want exact match for %q", usernameQuery, username)
	}
	orgQuery := request.GetQueries()[1].GetOrganizationIdQuery()
	if orgQuery.GetOrganizationId() != orgID {
		t.Fatalf("organization query = %+v, want %q", orgQuery, orgID)
	}
}

func assertApplicationLookupFilters(t *testing.T, request *appV2.ListApplicationsRequest, projectID, name string) {
	t.Helper()
	if request.GetPagination().GetLimit() != lookupPageSize || !request.GetPagination().GetAsc() {
		t.Fatalf("application pagination = %+v, want limit %d ascending", request.GetPagination(), lookupPageSize)
	}
	if len(request.GetFilters()) != 2 {
		t.Fatalf("application filter count = %d, want 2", len(request.GetFilters()))
	}
	projectFilter := request.GetFilters()[0].GetProjectIdFilter()
	if projectFilter.GetProjectId() != projectID {
		t.Fatalf("project filter = %+v, want %q", projectFilter, projectID)
	}
	nameFilter := request.GetFilters()[1].GetNameFilter()
	if nameFilter.GetName() != name || nameFilter.GetMethod() != filterV2.TextFilterMethod_TEXT_FILTER_METHOD_EQUALS {
		t.Fatalf("name filter = %+v, want exact match for %q", nameFilter, name)
	}
}

func userLookupResponse(total uint64, users ...*userV2.User) *userV2.ListUsersResponse {
	return &userV2.ListUsersResponse{
		Details: &objectV2.ListDetails{TotalResult: total},
		Result:  users,
	}
}

func applicationLookupResponse(total uint64, applications ...*appV2.Application) *appV2.ListApplicationsResponse {
	return &appV2.ListApplicationsResponse{
		Applications: applications,
		Pagination:   &filterV2.PaginationResponse{TotalResult: total},
	}
}
