# zitadel-grpc-auth

A small, opinionated Go module that wires Zitadel-backed authentication and
authorization into gRPC services — with one switch to turn it off.

```go
import (
    auth   "github.ibm.com/citius/zitadel-grpc-auth"
    "github.ibm.com/citius/zitadel-grpc-auth/client"
    "github.ibm.com/citius/zitadel-grpc-auth/server"
)
```

## Why

The Zitadel Go SDK gives you HTTP middleware and an introspecting authorizer.
What it doesn't give you, and what this module does:

- **gRPC unary + stream interceptors** (the SDK only ships `http.Handler`
  middleware).
- **An "auth off" mode** so the same call site works in dev, tests, and
  production.
- **Introspection caching** with TTL + LRU + singleflight so a chatty service
  doesn't hammer the IDP.
- **A per-method policy registry** with default-deny, public-method bypass, and
  composable `PolicyFunc`s.
- **Zero assumptions about your custom claim names.** Your action script is
  free to emit whatever shape it wants; you write a 5-line `PolicyFunc` to read
  it.

It is **not** a general OIDC framework. It is opaque tokens against Zitadel
introspection, for gRPC, with caching and policies. That's the whole scope.

## Quickstart — Server

```go
import (
    auth   "github.ibm.com/citius/zitadel-grpc-auth"
    "github.ibm.com/citius/zitadel-grpc-auth/server"
)

requireOp := func(op string) auth.PolicyFunc {
    return func(_ context.Context, _ string, c *auth.Claims) error {
        if !c.HasStringInSlice("urn:citius:permissions", op) {
            return auth.Forbidden("missing permission %q", op)
        }
        return nil
    }
}

srvOpts, closer, err := server.New(server.Config{
    RequireAuth:               os.Getenv("AUTH_ENABLED") == "true",
    Issuer:                    "http://localhost:8080",
    IntrospectionClientID:     apiClientID,
    IntrospectionClientSecret: apiClientSecret,
    Insecure:                  true,
    CacheTTL:                  30 * time.Second,
    CacheMaxEntries:           10_000,
    PublicMethods:             []string{"/citius.CitiusService/Healthz"},
    Policies: map[string][]auth.PolicyFunc{
        "/citius.CitiusService/Encrypt":   {requireOp("citius:encrypt")},
        "/citius.CitiusService/Decrypt":   {requireOp("citius:decrypt")},
        "/citius.CitiusService/CreateKey": {requireOp("citius:create-key")},
        "/citius.CitiusService/ListKeys":  {requireOp("citius:list-keys")},
    },
})
if err != nil { log.Fatal(err) }
defer closer.Close()

grpcSrv := grpc.NewServer(srvOpts...)
```

In handlers, retrieve claims for resource-level checks. The reference
deployment exposes two independent resource axes — encryption keys and
named service policies — so handlers run one `AuthorizeGlobPattern`
check per axis they touch:

```go
func (s *citiusServer) Encrypt(ctx context.Context, req *pb.EncryptRequest) (*pb.EncryptResponse, error) {
    c := auth.ClaimsFromContext(ctx)
    if err := auth.AuthorizeGlobPattern(req.KeyName,
        c.StringSlice("urn:citius:allowed_key_patterns"),
        c.StringSlice("urn:citius:deny_key_patterns"),
    ); err != nil {
        return nil, err
    }
    if req.PolicyName != "" {
        if err := auth.AuthorizeGlobPattern(req.PolicyName,
            c.StringSlice("urn:citius:allowed_policy_patterns"),
            c.StringSlice("urn:citius:deny_policy_patterns"),
        ); err != nil {
            return nil, err
        }
    }
    // ... do the work
}
```

## Quickstart — Client

```go
import (
    "github.ibm.com/citius/zitadel-grpc-auth/client"
)

authOpts, closer, err := client.New(ctx, client.Config{
    AttachToken:  os.Getenv("AUTH_ENABLED") == "true",
    Issuer:       "http://localhost:8080",
    ClientID:     userClientID,
    ClientSecret: userClientSecret,
    Scopes:       []string{"openid", "urn:zitadel:iam:org:project:id:" + projectID + ":aud"},
})
if err != nil { log.Fatal(err) }
defer closer.Close()

dialOpts := append([]grpc.DialOption{
    grpc.WithTransportCredentials(insecure.NewCredentials()),
}, authOpts...)
conn, _ := grpc.NewClient(target, dialOpts...)
```

## Authorization model

A `PolicyFunc` is the unit of authorization:

```go
type PolicyFunc func(ctx context.Context, method string, claims *Claims) error
```

The server `Config.Policies` map is `map[string][]PolicyFunc`. Each entry
reads as a top-to-bottom checklist of requirements for that method (implicit
AND, short-circuit on first error). Missing methods are denied by default —
this is intentional: every RPC in your service must make an explicit
authorization decision at registration time.

For OR semantics within a single requirement, wrap with `auth.Any(p1, p2,
...)`:

```go
"/svc/Read": {
    auth.Any(requireOp("svc:read"), requireOp("svc:admin")),
},
```

`Claims` is a thin typed wrapper around `map[string]any` (the introspection
response). The module ships **no** built-in policies — you write tiny
predicates against your own claim names.

| Helper                                          | Use                                                    |
| ----------------------------------------------- | ------------------------------------------------------ |
| `c.String(key)` / `c.StringSlice(key)`          | read a claim                                            |
| `c.HasStringInSlice(key, v)`                    | the most common predicate (e.g. permission lookup)      |
| `auth.AuthorizeGlobPattern(name, allow, deny)`  | resource-level check, deny-wins, glob support           |
| `auth.All(p1, p2, ...)` / `auth.Any(p1, p2)`    | compose policies                                        |
| `auth.Forbidden(fmt, ...)` / `auth.Unauthenticated(fmt, ...)` | construct properly-typed errors |

## Caching

Set `CacheTTL > 0` (and optionally `CacheMaxEntries`). The cache:

- Bounds each entry's TTL by `min(CacheTTL, token.exp - now)`, so it never
  serves a token past its own expiry.
- Caches negative outcomes (`active=false`) for the same TTL to avoid
  hammering Zitadel with bad tokens. Transport errors are NOT cached.
- Uses `singleflight` so N concurrent requests with the same uncached token
  result in exactly one introspection call.
- Keys by `sha256(token)`, so raw token bytes don't linger in cache keys or
  profiles.

Trade-off: changing a user's role takes effect at most `CacheTTL` later.
Set `CacheTTL = 0` to disable caching entirely (introspect every call).

## Auth on/off toggle

- `client.Config.AttachToken = false` → the dial options install
  pass-through interceptors. No token source is created, no IDP contact.
- `server.Config.RequireAuth = false` → the server options install
  pass-through interceptors. No introspection, no policies, empty claims in
  handler context.

In both cases the construction code at the call site is identical to the
"on" mode. Application code does not branch on auth state.

## Testing your policies

`PolicyFunc` is a pure function over `(ctx, method, *Claims)`:

```go
c := auth.NewClaims(map[string]any{"urn:citius:permissions": []any{"citius:read"}})
if err := requireOp("citius:read")(ctx, "/svc/Read", c); err != nil {
    t.Fatal(err)
}
```

No gRPC, no network, no Zitadel mocks needed.

## Layout

```
.
├── claims.go        Claims wrapper around the introspection map
├── context.go       ContextWithClaims / ClaimsFromContext
├── errors.go        ErrUnauthenticated, ErrForbidden, helpers
├── policy.go        PolicyFunc, All, Any, AuthorizeGlobPattern
├── redact.go        RedactToken (safe-for-logging)
├── client/          gRPC dial-side adapter
├── server/          gRPC server-side adapter
│   ├── server.go    Config, New
│   ├── introspector.go  HTTP introspector + interface
│   ├── interceptor.go   unary + stream + decision flow
│   └── cache.go     TTL + size-bounded + singleflight
└── internal/bearer/ Bearer header parsing
```

## Non-goals (deliberate)

- ❌ JWT validation (opaque tokens only)
- ❌ Multi-tenancy / multi-instance routing
- ❌ HTTP middleware (gRPC only)
- ❌ A general OIDC framework
- ❌ Push-based revocation (rely on cache TTL)
- ❌ Configuration loading (no env reading inside the module)

## License

See the parent project.
