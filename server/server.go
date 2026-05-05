// Package server provides gRPC server-side interceptors that authenticate
// incoming requests against Zitadel's OAuth2 introspection endpoint and
// enforce per-method authorization policies.
//
// When [Config.RequireAuth] is false, the returned options install pure
// pass-through interceptors: no introspection happens, no policies are
// evaluated, and the handler context carries no claims. Caller code that
// constructs the gRPC server is identical in both modes.
//
// Typical usage:
//
//	srvOpts, closer, err := server.New(server.Config{
//	    RequireAuth:               true,
//	    Issuer:                    "http://localhost:8080",
//	    IntrospectionClientID:     id,
//	    IntrospectionClientSecret: secret,
//	    Insecure:                  true,
//	    CacheTTL:                  30 * time.Second,
//	    CacheMaxEntries:           10_000,
//	    PublicMethods:             []string{"/svc/Healthz"},
//	    Policies: map[string][]auth.PolicyFunc{
//	        "/svc/Op": {requireOp("op")},
//	    },
//	})
//	if err != nil { return err }
//	defer closer.Close()
//	grpcSrv := grpc.NewServer(srvOpts...)
package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	auth "github.ibm.com/citius/zitadel-grpc-auth"
	"google.golang.org/grpc"
)

// Introspector is the abstraction over the Zitadel introspection endpoint.
// The default implementation ([NewSDKIntrospector]) uses the Zitadel Go SDK's
// introspection verifier. Tests and advanced deployments may substitute their
// own implementation (e.g. [NewHTTPIntrospector] or a test stub).
type Introspector interface {
	// Introspect validates the opaque bearer token and returns the
	// claims plus the token's expiration time. If the token is not
	// active, the returned error must wrap [auth.ErrUnauthenticated].
	// Network/server errors should be returned untouched (the interceptor
	// fails closed and translates them to codes.Internal).
	//
	// expiresAt is used by the cache to bound the cache entry's TTL — a
	// zero value means "no token-side expiry hint", in which case the
	// cache uses its configured TTL only.
	Introspect(ctx context.Context, token string) (claims *auth.Claims, expiresAt time.Time, err error)
}

// Config configures the server-side authentication and authorization
// pipeline.
type Config struct {
	// RequireAuth controls whether incoming RPCs are authenticated and
	// authorized. When true, every non-public RPC must carry a valid
	// bearer token AND satisfy every PolicyFunc registered for that
	// method.
	//
	// When false, the returned interceptors are pure pass-throughs: no
	// introspection is performed, no policies are consulted, and Claims
	// is empty in the handler context. Intended for local dev / tests
	// only.
	RequireAuth bool

	// Issuer is the Zitadel issuer URL, e.g. "http://localhost:8080".
	// Required when RequireAuth=true unless a custom Introspector is
	// supplied.
	Issuer string

	// IntrospectionClientID and IntrospectionClientSecret are the
	// credentials of a Zitadel API application used to call
	// /oauth/v2/introspect (HTTP Basic). Required when RequireAuth=true
	// unless a custom Introspector is supplied.
	IntrospectionClientID     string
	IntrospectionClientSecret string

	// Insecure permits plaintext HTTP for the introspection endpoint.
	// Production deployments must leave this false. Ignored when a
	// custom Introspector is supplied.
	Insecure bool

	// HTTPClient lets callers override the http.Client used by the
	// default introspector (e.g. to inject a transport with timeouts or
	// custom TLS config). If nil, http.DefaultClient is used.
	HTTPClient *http.Client

	// Introspector overrides the default SDK-backed introspector. When set,
	// Issuer, IntrospectionClientID, IntrospectionClientSecret, Insecure
	// and HTTPClient are ignored. Useful for tests and for plugging in a
	// Zitadel SDK-based authorizer.
	Introspector Introspector

	// CacheTTL bounds how long an introspection result may be reused.
	// The actual TTL of any single entry is min(CacheTTL,
	// token.exp - now). Zero disables caching (introspect every call).
	CacheTTL time.Duration

	// CacheMaxEntries bounds the in-memory introspection cache. Zero
	// disables caching. When CacheTTL > 0 and CacheMaxEntries == 0, a
	// sensible default of 10_000 is used.
	CacheMaxEntries int

	// Policies maps fully-qualified gRPC methods (e.g.
	// "/citius.CitiusService/Encrypt") to an ordered list of
	// authorization checks. Semantics:
	//
	//   - ALL policies in the slice must return nil for the RPC to
	//     proceed (implicit AND). The list reads as a checklist of
	//     requirements for that method.
	//   - Evaluation is short-circuit: the first non-nil error is
	//     returned and remaining policies are not evaluated.
	//   - An empty slice means "authenticated only, no authorization
	//     checks".
	//   - A method absent from this map is DENIED by default (unless
	//     listed in PublicMethods). This forces every RPC to make an
	//     explicit authorization decision at registration time.
	//
	// For OR semantics within a single requirement, use auth.Any(p1,
	// p2, ...) as one entry in the slice.
	Policies map[string][]auth.PolicyFunc

	// PublicMethods lists fully-qualified gRPC methods that bypass
	// authentication AND authorization entirely (e.g. "/svc/Healthz",
	// gRPC reflection methods). The handler runs with no claims in
	// context.
	PublicMethods []string

	// EnforceAuthOnReflection makes gRPC reflection RPCs
	// ("/grpc.reflection.v1.*", "/grpc.reflection.v1alpha.*") subject to
	// the same auth checks as application RPCs.
	//
	// The default is false, which means reflection bypasses auth so common
	// dev workflows (e.g. grpcurl listing services) work out of the box.
	// Set to true in production deployments that expose reflection but
	// want to gate it.
	EnforceAuthOnReflection bool

	// ExpectedIssuer, when non-empty, requires the introspected token's
	// "iss" claim to match exactly. This is defence-in-depth: a healthy
	// Zitadel will only return active=true for tokens it issued, but an
	// explicit issuer pin protects against misconfiguration (e.g. an
	// introspection client pointed at the wrong instance) and against a
	// future where multiple issuers feed the same introspection endpoint.
	ExpectedIssuer string

	// ExpectedAudience, when non-empty, requires the introspected token's
	// "aud" claim to contain at least one of the listed values. This is
	// the primary protection against cross-audience token reuse: a token
	// minted for a different API application in the same Zitadel project
	// will introspect as active=true, but its audience will not include
	// this service. Setting ExpectedAudience to the project audience
	// (e.g. "urn:zitadel:iam:org:project:id:<projectID>:aud") closes that
	// gap.
	ExpectedAudience []string
}

// Closer releases resources held by the server bundle (currently the
// introspection cache; reserved for forward-compatibility).
type Closer interface {
	Close() error
}

type noopCloser struct{}

func (noopCloser) Close() error { return nil }

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

// New returns gRPC server options that wire the server into the configured
// authentication and authorization mode. The returned [Closer] should be
// deferred to release any held resources.
//
// When cfg.RequireAuth is false, the returned options install no-op
// interceptors and the returned Closer is a no-op.
func New(cfg Config) ([]grpc.ServerOption, Closer, error) {
	if !cfg.RequireAuth {
		return []grpc.ServerOption{
			grpc.UnaryInterceptor(noopUnary),
			grpc.StreamInterceptor(noopStream),
		}, noopCloser{}, nil
	}

	intr := cfg.Introspector
	if intr == nil {
		built, err := buildDefaultIntrospector(cfg)
		if err != nil {
			return nil, nil, err
		}
		intr = built
	}

	cache := newCache(cfg.CacheTTL, effectiveMaxEntries(cfg))

	pub := make(map[string]struct{}, len(cfg.PublicMethods))
	for _, m := range cfg.PublicMethods {
		pub[m] = struct{}{}
	}

	enf := &enforcer{
		introspector:      intr,
		cache:             cache,
		policies:          cfg.Policies,
		publicMethods:     pub,
		enforceReflection: cfg.EnforceAuthOnReflection,
		expectedIssuer:    cfg.ExpectedIssuer,
		expectedAudience:  append([]string(nil), cfg.ExpectedAudience...),
	}

	return []grpc.ServerOption{
		grpc.UnaryInterceptor(enf.unary),
		grpc.StreamInterceptor(enf.stream),
	}, closerFunc(cache.Close), nil
}

func buildDefaultIntrospector(cfg Config) (Introspector, error) {
	var missing []string
	if cfg.Issuer == "" {
		missing = append(missing, "Issuer")
	}
	if cfg.IntrospectionClientID == "" {
		missing = append(missing, "IntrospectionClientID")
	}
	if cfg.IntrospectionClientSecret == "" {
		missing = append(missing, "IntrospectionClientSecret")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("server.Config: missing required fields when RequireAuth=true: %s", strings.Join(missing, ", "))
	}
	if !cfg.Insecure && !strings.HasPrefix(cfg.Issuer, "https://") {
		return nil, errors.New("server.Config: Issuer must be https:// (or set Insecure=true for local dev)")
	}
	if cfg.HTTPClient != nil {
		return NewHTTPIntrospector(cfg.Issuer, cfg.IntrospectionClientID, cfg.IntrospectionClientSecret, cfg.HTTPClient), nil
	}
	return NewSDKIntrospector(cfg.Issuer, cfg.IntrospectionClientID, cfg.IntrospectionClientSecret, cfg.Insecure)
}

func effectiveMaxEntries(cfg Config) int {
	if cfg.CacheTTL <= 0 {
		return 0
	}
	if cfg.CacheMaxEntries > 0 {
		return cfg.CacheMaxEntries
	}
	return 10_000
}
