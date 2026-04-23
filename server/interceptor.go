package server

import (
	"context"
	"strings"

	auth "github.ibm.com/citius/zitadel-grpc-auth"
	"github.ibm.com/citius/zitadel-grpc-auth/internal/bearer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// enforcer holds the wired-up authentication+authorization pipeline. Both
// unary and stream interceptors share this state.
type enforcer struct {
	introspector      Introspector
	cache             *introspectionCache
	policies          map[string][]auth.PolicyFunc
	publicMethods     map[string]struct{}
	enforceReflection bool // false (default) → reflection bypasses auth
}

// authorize is the core decision: does the call described by (ctx, method)
// proceed? Returns a context augmented with claims (when authentication
// happened) and an error if the call should be denied.
//
// Decision flow (matches MODULE_PLAN.md §5):
//
//  1. Public method (or skipped reflection) → allow with empty context
//  2. Extract bearer; missing/malformed → Unauthenticated
//  3. Resolve claims via cache → introspector; not active → Unauthenticated
//  4. Look up policies[method]:
//     - method not in map → PermissionDenied (default deny)
//     - empty slice      → allow (auth-only)
//     - non-empty slice  → run each in order, short-circuit on first error
func (e *enforcer) authorize(ctx context.Context, method string) (context.Context, error) {
	if e.isPublic(method) {
		return ctx, nil
	}

	md, _ := metadata.FromIncomingContext(ctx)
	token := bearer.FromIncomingMetadata(md)
	if token == "" {
		return ctx, status.Error(codes.Unauthenticated, "missing or malformed bearer token")
	}

	claims, err := e.cache.resolve(ctx, token, e.introspector)
	if err != nil {
		return ctx, toGRPCStatus(err)
	}

	policies, registered := e.policies[method]
	if !registered {
		return ctx, status.Errorf(codes.PermissionDenied, "no policy registered for method %s", method)
	}

	for _, p := range policies {
		if p == nil {
			continue
		}
		if err := p(ctx, method, claims); err != nil {
			return ctx, toGRPCStatus(err)
		}
	}

	return auth.ContextWithClaims(ctx, claims), nil
}

func (e *enforcer) isPublic(method string) bool {
	if _, ok := e.publicMethods[method]; ok {
		return true
	}
	if !e.enforceReflection &&
		(strings.HasPrefix(method, "/grpc.reflection.v1.") ||
			strings.HasPrefix(method, "/grpc.reflection.v1alpha.")) {
		return true
	}
	return false
}

// unary is the grpc.UnaryServerInterceptor implementation.
func (e *enforcer) unary(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	newCtx, err := e.authorize(ctx, info.FullMethod)
	if err != nil {
		return nil, err
	}
	return handler(newCtx, req)
}

// stream is the grpc.StreamServerInterceptor implementation. It wraps the
// server stream so that handlers retrieving claims via
// auth.ClaimsFromContext(ss.Context()) see the augmented context.
func (e *enforcer) stream(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	newCtx, err := e.authorize(ss.Context(), info.FullMethod)
	if err != nil {
		return err
	}
	return handler(srv, &wrappedStream{ServerStream: ss, ctx: newCtx})
}

type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedStream) Context() context.Context { return w.ctx }

// toGRPCStatus translates an internal/auth-domain error into a gRPC status
// error. The mapping is:
//
//   - already a gRPC status                  → returned untouched
//   - wraps auth.ErrUnauthenticated          → codes.Unauthenticated
//   - wraps auth.ErrForbidden                → codes.PermissionDenied
//   - anything else                          → codes.Internal
//
// The Internal mapping is conservative: an unexpected error from an
// introspector or policy is a server-side failure, not the client's fault.
//
// Note: for codes.Internal we currently surface err.Error() to the gRPC
// client. This can leak server-side detail (e.g. "dial tcp 10.0.0.5: connect
// refused"). Operators uncomfortable with that should wrap their introspector
// to translate transport errors into auth.Unauthenticated, or fork this
// helper. Logging the original error is a future hook (see MODULE_PLAN §10).
func toGRPCStatus(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := status.FromError(err); ok {
		return err
	}
	switch {
	case auth.IsUnauthenticated(err):
		return status.Error(codes.Unauthenticated, err.Error())
	case auth.IsForbidden(err):
		return status.Error(codes.PermissionDenied, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}

// noopUnary forwards every unary RPC untouched. Used in disabled mode.
func noopUnary(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	return handler(ctx, req)
}

// noopStream forwards every stream RPC untouched. Used in disabled mode.
func noopStream(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	return handler(srv, ss)
}

// Compile-time assertion that we satisfy grpc's interceptor signatures.
var (
	_ grpc.UnaryServerInterceptor  = (*enforcer)(nil).unary
	_ grpc.StreamServerInterceptor = (*enforcer)(nil).stream
)
