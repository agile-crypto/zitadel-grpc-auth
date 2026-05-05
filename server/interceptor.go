package server

import (
	"context"
	"strings"
	"time"

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
	introspector       Introspector
	cache              *introspectionCache
	policies           map[string][]auth.PolicyFunc
	publicMethods      map[string]struct{}
	allowUnauthReflect bool     // false (default) → reflection requires auth like any other RPC
	expectedIssuer     string   // "" disables the check
	expectedAudience   []string // empty disables the check
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

	// Defence-in-depth: a healthy Zitadel will only return active=true
	// for a non-expired token, but a stale cache entry, a clock skew on
	// the introspecting host, or a misbehaving custom Introspector could
	// surface an expired token here. Recheck before honouring it.
	if exp := claims.Expiration(); !exp.IsZero() && time.Now().After(exp) {
		return ctx, status.Error(codes.Unauthenticated, "token expired")
	}

	if e.expectedIssuer != "" && claims.Issuer() != e.expectedIssuer {
		return ctx, status.Error(codes.Unauthenticated, "token issuer not accepted")
	}
	if len(e.expectedAudience) > 0 && !audienceMatches(claims.StringSlice("aud"), e.expectedAudience) {
		return ctx, status.Error(codes.Unauthenticated, "token audience not accepted")
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
	if e.allowUnauthReflect &&
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
//   - wraps auth.ErrUnauthenticated          → codes.Unauthenticated
//   - wraps auth.ErrForbidden                → codes.PermissionDenied
//   - already a caller-facing gRPC status    → returned untouched
//     (Unauthenticated, PermissionDenied, InvalidArgument, NotFound,
//     FailedPrecondition, ResourceExhausted)
//   - anything else                          → codes.Internal with a
//     generic message (the original error is intentionally NOT surfaced
//     to the client to avoid leaking server-side detail such as upstream
//     hostnames, ports, or stack-shaped errors from the introspector).
//
// The Internal mapping is conservative: an unexpected error from an
// introspector or policy is a server-side failure, not the client's fault.
func toGRPCStatus(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case auth.IsUnauthenticated(err):
		return status.Error(codes.Unauthenticated, err.Error())
	case auth.IsForbidden(err):
		return status.Error(codes.PermissionDenied, err.Error())
	}
	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.Unauthenticated,
			codes.PermissionDenied,
			codes.InvalidArgument,
			codes.NotFound,
			codes.FailedPrecondition,
			codes.ResourceExhausted:
			return err
		}
	}
	return status.Error(codes.Internal, "internal authorization error")
}

// audienceMatches reports whether the token's audience list intersects the
// configured expected-audience set. The caller-side check is intentionally
// strict (any single match is sufficient) so callers can configure both a
// project audience and a per-API audience without forcing both to appear.
func audienceMatches(tokenAud, expected []string) bool {
	if len(tokenAud) == 0 {
		return false
	}
	for _, want := range expected {
		for _, got := range tokenAud {
			if got == want {
				return true
			}
		}
	}
	return false
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
