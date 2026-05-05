package auth

import (
	"context"
	"strings"
)

// PolicyFunc is the unit of authorization. It receives the call's context,
// the fully-qualified gRPC method (e.g. "/citius.CitiusService/Encrypt"),
// and the introspected [*Claims] for the caller. A nil return allows the
// RPC; any non-nil return denies it.
//
// Errors are translated by the server interceptor into gRPC status codes:
//
//   - Wrapping [ErrUnauthenticated] (or returning [ErrUnauthenticated]) →
//     codes.Unauthenticated
//   - Wrapping [ErrForbidden] (or returning [ErrForbidden]) →
//     codes.PermissionDenied
//   - Any other error → codes.Internal
//
// Use the [Forbidden] and [Unauthenticated] helpers to produce well-typed
// errors with formatted messages.
//
// Policies should be pure functions over their inputs: no I/O, no global
// state, no panics. They are unit-testable in isolation, with no gRPC or
// network mocks required.
type PolicyFunc func(ctx context.Context, method string, claims *Claims) error

// All composes policies with AND semantics: every policy must return nil for
// the composite to allow the RPC. Evaluation is short-circuit — the first
// non-nil error is returned and the remaining policies are not called.
//
// All() with no arguments returns a policy that always allows.
func All(policies ...PolicyFunc) PolicyFunc {
	return func(ctx context.Context, method string, claims *Claims) error {
		for _, p := range policies {
			if p == nil {
				continue
			}
			if err := p(ctx, method, claims); err != nil {
				return err
			}
		}
		return nil
	}
}

// Any composes policies with OR semantics: the composite allows if any one
// returns nil. If every policy returns an error, the LAST non-nil error is
// returned (the assumption being it's the most specific failure to surface).
//
// Any() with no arguments returns a policy that always denies with
// [ErrForbidden].
func Any(policies ...PolicyFunc) PolicyFunc {
	return func(ctx context.Context, method string, claims *Claims) error {
		if len(policies) == 0 {
			return Forbidden("no policies registered for Any composition on %s", method)
		}
		var lastErr error
		for _, p := range policies {
			if p == nil {
				continue
			}
			err := p(ctx, method, claims)
			if err == nil {
				return nil
			}
			lastErr = err
		}
		return lastErr
	}
}

// AuthorizeGlobPattern is a resource-level helper for the very common case of
// "may this caller act on a named resource?" given allow- and deny-lists of
// glob patterns. Returns nil if name is allowed, or [ErrForbidden] otherwise.
//
// Semantics:
//
//   - Deny patterns take precedence: any match in deny → forbidden.
//   - "*" matches everything.
//   - "prefix-*" matches anything starting with "prefix-".
//   - "*-suffix" matches anything ending with "-suffix".
//   - Otherwise an exact match is required.
//   - An empty allow list is interpreted as "allow all (subject to deny)".
//     This matches the conservative-but-pragmatic semantic used by the
//     original citius example: a caller with no positive grants is treated
//     as having implicit access UNLESS they were explicitly denied.
//
// SECURITY WARNING: the empty-allow-list semantics make this helper
// fail-open. If a caller's allow patterns come from a token claim (the
// expected use), then any condition that prevents that claim from being
// populated — a misconfigured Zitadel action, a renamed namespace, a
// freshly-onboarded user whose metadata hasn't replicated, an introspector
// that returns a stripped-down claim set — turns into UNRESTRICTED ACCESS.
// In production, prefer [AuthorizeGlobPatternStrict], which denies on an
// empty allow list. This function is preserved for the rare case where
// "no grants means anything" really is the desired policy (e.g. an
// internally-trusted health endpoint).
//
// This helper lives in the module because the "deny-wins, allow-list with
// glob" pattern is reusable across many resource types; it is NOT bound to
// any particular claim name.
func AuthorizeGlobPattern(name string, allow, deny []string) error {
	for _, p := range deny {
		if matchGlob(p, name) {
			return Forbidden("resource %q denied by pattern %q", name, p)
		}
	}
	if len(allow) == 0 {
		return nil
	}
	for _, p := range allow {
		if matchGlob(p, name) {
			return nil
		}
	}
	return Forbidden("resource %q does not match any allow pattern", name)
}

// AuthorizeGlobPatternStrict is the recommended default-deny variant of
// [AuthorizeGlobPattern]. It applies the same deny-wins semantics, but an
// empty allow list yields [ErrForbidden] instead of allowing.
//
// Use this whenever the allow list comes from a claim or any other source
// outside the server's startup configuration: a missing/typo claim then
// fails closed instead of granting unrestricted access.
func AuthorizeGlobPatternStrict(name string, allow, deny []string) error {
	for _, p := range deny {
		if matchGlob(p, name) {
			return Forbidden("resource %q denied by pattern %q", name, p)
		}
	}
	if len(allow) == 0 {
		return Forbidden("resource %q has no allow patterns", name)
	}
	for _, p := range allow {
		if matchGlob(p, name) {
			return nil
		}
	}
	return Forbidden("resource %q does not match any allow pattern", name)
}

// matchGlob is a tiny, intentionally limited glob: "*" anywhere, prefix-*,
// *-suffix, or exact. We avoid a full glob library to keep the dependency
// surface minimal and the matching predictable.
func matchGlob(pattern, name string) bool {
	if pattern == "*" {
		return true
	}
	hasPrefixStar := strings.HasPrefix(pattern, "*")
	hasSuffixStar := strings.HasSuffix(pattern, "*")
	switch {
	case hasPrefixStar && hasSuffixStar:
		// "*foo*" — substring match
		inner := pattern[1 : len(pattern)-1]
		return strings.Contains(name, inner)
	case hasSuffixStar:
		return strings.HasPrefix(name, pattern[:len(pattern)-1])
	case hasPrefixStar:
		return strings.HasSuffix(name, pattern[1:])
	default:
		return pattern == name
	}
}
