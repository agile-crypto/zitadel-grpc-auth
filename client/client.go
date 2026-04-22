// Package client provides gRPC dial-side interceptors that attach a Zitadel
// bearer token (acquired via the OAuth2 client_credentials grant) to every
// outgoing RPC.
//
// When [Config.AttachToken] is false, the returned dial options install
// pure pass-through interceptors and no token source is created — useful
// for local development, tests, or environments without an IDP. The caller
// code that constructs the gRPC client is identical in both modes.
//
// Typical usage:
//
//	authOpts, closer, err := client.New(ctx, client.Config{
//	    AttachToken:  true,
//	    Issuer:       "http://localhost:8080",
//	    ClientID:     id,
//	    ClientSecret: secret,
//	    Scopes:       []string{"openid", "urn:zitadel:iam:org:project:id:" + projectID + ":aud"},
//	    Insecure:     true,
//	})
//	if err != nil { return err }
//	defer closer.Close()
//
//	dialOpts := append([]grpc.DialOption{
//	    grpc.WithTransportCredentials(insecure.NewCredentials()),
//	}, authOpts...)
//	conn, err := grpc.NewClient(target, dialOpts...)
package client

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// Config configures a gRPC client's outgoing authentication.
//
// All fields except AttachToken are required when AttachToken is true.
type Config struct {
	// AttachToken controls whether the client acquires a token from Zitadel
	// and attaches it as `authorization: Bearer <token>` on every outgoing
	// RPC.
	//
	// When false, the returned interceptors are pure pass-throughs — no
	// token source is created, no IDP connection is made, no metadata is
	// injected. Useful for local dev, tests, or environments without an
	// IDP. The grpc.NewClient(...) call site is identical in both modes.
	AttachToken bool

	// Issuer is the Zitadel issuer URL, e.g. "http://localhost:8080" or
	// "https://my-instance.zitadel.cloud". Required when AttachToken=true.
	// The token endpoint is derived as Issuer + "/oauth/v2/token".
	Issuer string

	// ClientID and ClientSecret are the credentials of a Zitadel service
	// user used for the client_credentials grant. Required when
	// AttachToken=true.
	ClientID     string
	ClientSecret string

	// Scopes requested when acquiring the token. A typical set for Zitadel
	// is ["openid", "urn:zitadel:iam:org:project:id:<projectID>:aud"]. The
	// project audience scope is required for tokens to be accepted by APIs
	// configured against that project.
	Scopes []string

	// TokenEndpoint, if set, overrides the default Issuer + "/oauth/v2/token".
	// Useful in tests with a fake token endpoint.
	TokenEndpoint string
}

// Closer releases any resources (currently the cached oauth2 token) held by
// the client. It is safe to call Close more than once.
type Closer interface {
	Close() error
}

// noopCloser is returned in disabled mode.
type noopCloser struct{}

func (noopCloser) Close() error { return nil }

// tokenSourceCloser is returned in enabled mode. The underlying
// oauth2.TokenSource has no Close method (tokens are held in memory only),
// so Close is currently a no-op but the interface is preserved so future
// versions can release resources without an API break.
type tokenSourceCloser struct{}

func (tokenSourceCloser) Close() error { return nil }

// New returns gRPC dial options that wire the client into the configured
// authentication mode. The returned [Closer] should be deferred to release
// resources held by the token source.
//
// The ctx argument is the LIFETIME context of the token source — token
// refreshes are issued with this context. Pass a long-lived context (e.g.
// the application's root context), NOT a per-request context. Cancelling
// ctx will cause subsequent token refreshes to fail.
//
// When cfg.AttachToken is false, the returned options install no-op unary
// and stream interceptors and the returned Closer is a no-op. The caller's
// code does not need to branch on the auth mode.
//
// When cfg.AttachToken is true, this validates that Issuer, ClientID and
// ClientSecret are set and lazily acquires tokens via the OAuth2
// client_credentials grant. Tokens are cached and refreshed automatically
// by oauth2.ReuseTokenSource.
func New(ctx context.Context, cfg Config) ([]grpc.DialOption, Closer, error) {
	if !cfg.AttachToken {
		return []grpc.DialOption{
			grpc.WithUnaryInterceptor(noopUnary),
			grpc.WithStreamInterceptor(noopStream),
		}, noopCloser{}, nil
	}

	if err := cfg.validate(); err != nil {
		return nil, nil, err
	}

	tokenURL := cfg.TokenEndpoint
	if tokenURL == "" {
		tokenURL = strings.TrimRight(cfg.Issuer, "/") + "/oauth/v2/token"
	}

	cc := clientcredentials.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		TokenURL:     tokenURL,
		Scopes:       cfg.Scopes,
	}
	// ReuseTokenSource caches tokens until expiry and refreshes
	// automatically on next use. Pass a nil seed token so the first call
	// triggers a real fetch.
	src := oauth2.ReuseTokenSource(nil, cc.TokenSource(ctx))

	return []grpc.DialOption{
		grpc.WithUnaryInterceptor(unaryAttachToken(src)),
		grpc.WithStreamInterceptor(streamAttachToken(src)),
	}, tokenSourceCloser{}, nil
}

func (c Config) validate() error {
	var missing []string
	if c.Issuer == "" {
		missing = append(missing, "Issuer")
	}
	if c.ClientID == "" {
		missing = append(missing, "ClientID")
	}
	if c.ClientSecret == "" {
		missing = append(missing, "ClientSecret")
	}
	if len(missing) > 0 {
		return fmt.Errorf("client.Config: missing required fields when AttachToken=true: %s", strings.Join(missing, ", "))
	}
	return nil
}

// unaryAttachToken returns a unary interceptor that fetches a token from src
// (using cached/refreshed values) and appends an Authorization: Bearer
// header to outgoing metadata.
func unaryAttachToken(src oauth2.TokenSource) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		ctx, err := withBearer(ctx, src)
		if err != nil {
			return err
		}
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

func streamAttachToken(src oauth2.TokenSource) grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		ctx, err := withBearer(ctx, src)
		if err != nil {
			return nil, err
		}
		return streamer(ctx, desc, cc, method, opts...)
	}
}

func withBearer(ctx context.Context, src oauth2.TokenSource) (context.Context, error) {
	tok, err := src.Token()
	if err != nil {
		return nil, fmt.Errorf("client: token acquisition failed: %w", err)
	}
	if tok == nil || tok.AccessToken == "" {
		return nil, errors.New("client: token source returned empty token")
	}
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+tok.AccessToken), nil
}

// noopUnary is the disabled-mode unary interceptor: forwards every call
// untouched.
func noopUnary(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	return invoker(ctx, method, req, reply, cc, opts...)
}

// noopStream is the disabled-mode stream interceptor: forwards untouched.
func noopStream(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return streamer(ctx, desc, cc, method, opts...)
}
