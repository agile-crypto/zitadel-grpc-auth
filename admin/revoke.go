package admin

import (
	"context"
	"fmt"
	"strings"

	authzV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/authorization/v2"
	userV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	"google.golang.org/grpc/codes"
)

func (c *Client) Revoke(ctx context.Context, username string, mode RevokeMode) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return fmt.Errorf("admin.Revoke: username is required")
	}
	user, err := c.lookupUserByUsername(ctx, username)
	if err != nil {
		return fmt.Errorf("admin.Revoke: lookup user: %w", err)
	}
	if user == nil {
		return nil
	}

	listed, err := c.api.authorizations.ListAuthorizations(ctx, &authzV2.ListAuthorizationsRequest{})
	if err != nil {
		return fmt.Errorf("admin.Revoke: list authorizations: %w", err)
	}
	for _, authz := range listed.GetAuthorizations() {
		if authz.GetUser().GetId() != user.GetUserId() {
			continue
		}
		_, err := c.api.authorizations.DeleteAuthorization(ctx, &authzV2.DeleteAuthorizationRequest{Id: authz.GetId()})
		if err != nil && !isStatusCode(err, codes.NotFound) {
			return fmt.Errorf("admin.Revoke: delete authorization %s: %w", authz.GetId(), err)
		}
	}

	namespace := normalizeNamespace("", c.cfg.Namespace)
	_, err = c.api.users.DeleteUserMetadata(ctx, &userV2.DeleteUserMetadataRequest{
		UserId: user.GetUserId(),
		Keys:   []string{keyAccessMetadataKey(namespace), policyAccessMetadataKey(namespace)},
	})
	if err != nil && !isStatusCode(err, codes.NotFound) {
		return fmt.Errorf("admin.Revoke: delete metadata: %w", err)
	}

	if mode == DeleteUser {
		_, err = c.api.users.DeleteUser(ctx, &userV2.DeleteUserRequest{UserId: user.GetUserId()})
		if err != nil && !isStatusCode(err, codes.NotFound) {
			return fmt.Errorf("admin.Revoke: delete user: %w", err)
		}
	}
	return nil
}

func (c *Client) lookupUserByUsername(ctx context.Context, username string) (*userV2.User, error) {
	// NOTE: same single-page caveat as ensureMachineUser — see the
	// comment there. For >1-page organisations this lookup needs a
	// server-side username filter.
	resp, err := c.api.users.ListUsers(ctx, &userV2.ListUsersRequest{})
	if err != nil {
		return nil, err
	}
	for _, user := range resp.GetResult() {
		if user.GetUsername() == username {
			return user, nil
		}
	}
	return nil, nil
}
