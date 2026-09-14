package admin

import (
	"context"
	"fmt"
	"strings"

	appV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/application/v2"
	filterV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/filter/v2"
	objectV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/object/v2"
	userV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
)

const lookupPageSize uint32 = 100

func (c *Client) lookupUserByUsername(ctx context.Context, orgID, username string) (*userV2.User, error) {
	username = strings.TrimSpace(username)
	var match *userV2.User
	var offset uint64
	for {
		resp, err := c.api.users.ListUsers(ctx, userLookupRequest(orgID, username, offset))
		if err != nil {
			return nil, err
		}
		for _, user := range resp.GetResult() {
			if user.GetUsername() != username {
				continue
			}
			if match != nil {
				return nil, fmt.Errorf("%w: multiple users named %q in organization %q", ErrAmbiguousResource, username, orgID)
			}
			match = user
		}

		next := offset + uint64(len(resp.GetResult()))
		if paginationComplete(next, len(resp.GetResult()), resp.GetDetails().GetTotalResult()) {
			return match, nil
		}
		if next == offset {
			return nil, fmt.Errorf("admin: user lookup pagination did not advance")
		}
		offset = next
	}
}

func userLookupRequest(orgID, username string, offset uint64) *userV2.ListUsersRequest {
	queries := []*userV2.SearchQuery{{
		Query: &userV2.SearchQuery_UserNameQuery{UserNameQuery: &userV2.UserNameQuery{
			UserName: username,
			Method:   objectV2.TextQueryMethod_TEXT_QUERY_METHOD_EQUALS,
		}},
	}}
	if orgID != "" {
		queries = append(queries, &userV2.SearchQuery{
			Query: &userV2.SearchQuery_OrganizationIdQuery{OrganizationIdQuery: &userV2.OrganizationIdQuery{OrganizationId: orgID}},
		})
	}
	return &userV2.ListUsersRequest{
		Query:   &objectV2.ListQuery{Offset: offset, Limit: lookupPageSize, Asc: true},
		Queries: queries,
	}
}

func (c *Client) lookupApplicationByName(ctx context.Context, projectID, name string) (*appV2.Application, error) {
	name = strings.TrimSpace(name)
	var match *appV2.Application
	var offset uint64
	for {
		resp, err := c.api.applications.ListApplications(ctx, applicationLookupRequest(projectID, name, offset))
		if err != nil {
			return nil, err
		}
		for _, app := range resp.GetApplications() {
			if app.GetProjectId() != projectID || app.GetName() != name {
				continue
			}
			if match != nil {
				return nil, fmt.Errorf("%w: multiple applications named %q in project %q", ErrAmbiguousResource, name, projectID)
			}
			match = app
		}

		next := offset + uint64(len(resp.GetApplications()))
		if paginationComplete(next, len(resp.GetApplications()), resp.GetPagination().GetTotalResult()) {
			return match, nil
		}
		if next == offset {
			return nil, fmt.Errorf("admin: application lookup pagination did not advance")
		}
		offset = next
	}
}

func applicationLookupRequest(projectID, name string, offset uint64) *appV2.ListApplicationsRequest {
	return &appV2.ListApplicationsRequest{
		Pagination: &filterV2.PaginationRequest{Offset: offset, Limit: lookupPageSize, Asc: true},
		Filters: []*appV2.ApplicationSearchFilter{
			{Filter: &appV2.ApplicationSearchFilter_ProjectIdFilter{ProjectIdFilter: &appV2.ProjectIDFilter{ProjectId: projectID}}},
			{Filter: &appV2.ApplicationSearchFilter_NameFilter{NameFilter: &appV2.ApplicationNameFilter{
				Name:   name,
				Method: filterV2.TextFilterMethod_TEXT_FILTER_METHOD_EQUALS,
			}}},
		},
	}
}

func paginationComplete(next uint64, resultCount int, total uint64) bool {
	if total > 0 {
		return next >= total
	}
	return resultCount < int(lookupPageSize)
}
