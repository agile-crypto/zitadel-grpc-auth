package admin

import (
	"context"
	"errors"
	"testing"

	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type triggerActionSetterFunc func(context.Context, *management.SetTriggerActionsRequest, ...grpc.CallOption) (*management.SetTriggerActionsResponse, error)

func (f triggerActionSetterFunc) SetTriggerActions(ctx context.Context, request *management.SetTriggerActionsRequest, options ...grpc.CallOption) (*management.SetTriggerActionsResponse, error) {
	return f(ctx, request, options...)
}

func TestSetTriggerActionsTreatsNoChangesAsSuccess(t *testing.T) {
	setter := triggerActionSetterFunc(func(context.Context, *management.SetTriggerActionsRequest, ...grpc.CallOption) (*management.SetTriggerActionsResponse, error) {
		return nil, status.Error(codes.FailedPrecondition, "No Changes (COMMAND-Nfh52)")
	})

	if err := setTriggerActions(context.Background(), setter, &management.SetTriggerActionsRequest{}); err != nil {
		t.Fatalf("setTriggerActions() error = %v, want nil", err)
	}
}

func TestIsNoChangesStatus(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "Zitadel idempotent action trigger response",
			err:  status.Error(codes.FailedPrecondition, "No Changes (COMMAND-Nfh52)"),
			want: true,
		},
		{
			name: "different failed precondition",
			err:  status.Error(codes.FailedPrecondition, "project is inactive"),
		},
		{
			name: "same message with different status code",
			err:  status.Error(codes.Internal, "No Changes (COMMAND-Nfh52)"),
		},
		{
			name: "non-gRPC error",
			err:  errors.New("No Changes (COMMAND-Nfh52)"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNoChangesStatus(tt.err); got != tt.want {
				t.Fatalf("isNoChangesStatus() = %v, want %v", got, tt.want)
			}
		})
	}
}
