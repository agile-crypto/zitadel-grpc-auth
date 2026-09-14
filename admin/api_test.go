package admin

import (
	"context"
	"io"
	"log/slog"
	"testing"

	userV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	"google.golang.org/grpc"
)

type fakeUserService struct {
	userService
	listUsers   func(context.Context, *userV2.ListUsersRequest) (*userV2.ListUsersResponse, error)
	setPassword func(context.Context, *userV2.SetPasswordRequest) (*userV2.SetPasswordResponse, error)
}

func (f *fakeUserService) ListUsers(ctx context.Context, in *userV2.ListUsersRequest, _ ...grpc.CallOption) (*userV2.ListUsersResponse, error) {
	return f.listUsers(ctx, in)
}

func (f *fakeUserService) SetPassword(ctx context.Context, in *userV2.SetPasswordRequest, _ ...grpc.CallOption) (*userV2.SetPasswordResponse, error) {
	return f.setPassword(ctx, in)
}

func TestClientUsesInjectedServices(t *testing.T) {
	var setPasswordRequest *userV2.SetPasswordRequest
	users := &fakeUserService{
		listUsers: func(context.Context, *userV2.ListUsersRequest) (*userV2.ListUsersResponse, error) {
			return &userV2.ListUsersResponse{Result: []*userV2.User{{
				UserId:   "human-1",
				Username: "producer",
				Type:     &userV2.User_Human{Human: &userV2.HumanUser{}},
			}}}, nil
		},
		setPassword: func(_ context.Context, in *userV2.SetPasswordRequest) (*userV2.SetPasswordResponse, error) {
			setPasswordRequest = in
			return &userV2.SetPasswordResponse{}, nil
		},
	}
	client := &Client{
		api:    adminServices{users: users},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	err := client.ResetHumanPassword(context.Background(), ResetHumanPasswordInput{
		Username:    "producer",
		NewPassword: "new-password",
	})
	if err != nil {
		t.Fatalf("ResetHumanPassword: %v", err)
	}
	if setPasswordRequest == nil {
		t.Fatal("SetPassword was not called")
	}
	if setPasswordRequest.GetUserId() != "human-1" {
		t.Fatalf("SetPassword user ID = %q, want human-1", setPasswordRequest.GetUserId())
	}
}

func TestClientCloseUsesInjectedCloser(t *testing.T) {
	closed := false
	client := &Client{api: adminServices{close: func() error {
		closed = true
		return nil
	}}}
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !closed {
		t.Fatal("injected closer was not called")
	}
	if err := (*Client)(nil).Close(); err != nil {
		t.Fatalf("nil Client.Close: %v", err)
	}
}
