// Package auth is the domain core of zitadel-grpc-auth: a Zitadel-backed
// authentication and authorization toolkit for gRPC services.
//
// The root package exposes only domain types (no I/O, no transport):
//
//   - [Claims] is a typed wrapper around an OIDC introspection response.
//   - [PolicyFunc] is the authorization contract; applications register
//     policies per fully-qualified gRPC method on the server side.
//   - [ErrUnauthenticated] and [ErrForbidden] are the sentinel errors that
//     server interceptors translate into gRPC status codes.
//   - Helpers ([All], [Any], [AuthorizeGlobPattern], [Forbidden],
//     [Unauthenticated]) compose policies and decisions.
//
// Transport-specific code lives in the subpackages:
//
//   - [github.com/agile-crypto/zitadel-grpc-auth/client] — gRPC dial-side
//     interceptors that attach bearer tokens via the OAuth2
//     client-credentials flow.
//   - [github.com/agile-crypto/zitadel-grpc-auth/server] — gRPC server-side
//     interceptors that introspect tokens against Zitadel, cache results,
//     and enforce per-method policies.
//
// Both subpackages support an "auth off" mode (server.Config.RequireAuth =
// false, client.Config.AttachToken = false) in which the returned
// interceptors are pure pass-throughs. Caller code is identical in both
// modes.
package auth
