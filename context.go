package auth

import "context"

// claimsCtxKey is the context key under which server interceptors stash the
// caller's [*Claims] before invoking the handler. The unexported zero-size
// struct ensures collision-free key namespacing.
type claimsCtxKey struct{}

// ContextWithClaims returns a child of ctx that carries the given claims. It
// is intended for use by server interceptors; handlers retrieve claims via
// [ClaimsFromContext]. Exported so that test harnesses can also inject
// claims directly.
func ContextWithClaims(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, claimsCtxKey{}, c)
}

// ClaimsFromContext returns the [*Claims] previously stashed by a server
// interceptor, or nil if none is present. A nil return is safe to call any
// [Claims] accessor on (every accessor handles the nil receiver), so
// handlers do not need to nil-check before reading claims.
func ClaimsFromContext(ctx context.Context) *Claims {
	c, _ := ctx.Value(claimsCtxKey{}).(*Claims)
	return c
}
