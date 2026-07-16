// Package greeter_e2e holds an end-to-end test that boots the example
// greeter server in-process (with a fake introspector) and drives it with
// the example client wiring. It exists to:
//
//  1. Prove the example code compiles and works as a smoke test that runs
//     in CI without needing a live Zitadel instance.
//  2. Demonstrate how to integration-test a service that uses
//     zitadel-grpc-auth: substitute server.Config.Introspector with a
//     fake, and skip the client.AttachToken plumbing by injecting a raw
//     bearer header from the test.
package greeter_e2e

import (
	"context"
	"net"
	"testing"
	"time"

	auth "github.com/agile-crypto/zitadel-grpc-auth"
	pb "github.com/agile-crypto/zitadel-grpc-auth/examples/greeter/pb"
	"github.com/agile-crypto/zitadel-grpc-auth/server"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	methodHealthz = "/greeter.v1.Greeter/Healthz"
	methodHello   = "/greeter.v1.Greeter/Hello"
	methodAdmin   = "/greeter.v1.Greeter/Admin"
)

// fakeIntrospector returns canned claims based on a small in-test token →
// claims table.
type fakeIntrospector struct {
	tokens map[string]map[string]any
}

func (f *fakeIntrospector) Introspect(_ context.Context, token string) (*auth.Claims, time.Time, error) {
	raw, ok := f.tokens[token]
	if !ok {
		return auth.NewClaims(map[string]any{"active": false}), time.Time{},
			auth.Unauthenticated("unknown token")
	}
	claims := auth.NewClaims(raw)
	return claims, claims.Expiration(), nil
}

// greeterImpl is duplicated here intentionally rather than imported from
// `examples/greeter/server` (which is `package main`) — main packages can't
// be imported. In a real project you'd extract the implementation into its
// own importable package; for an example, the duplication is the cheaper
// trade-off.
type greeterImpl struct {
	pb.UnimplementedGreeterServer
}

func (g *greeterImpl) Healthz(_ context.Context, _ *pb.HealthzRequest) (*pb.HealthzResponse, error) {
	return &pb.HealthzResponse{Status: "ok"}, nil
}

func (g *greeterImpl) Hello(ctx context.Context, req *pb.HelloRequest) (*pb.HelloResponse, error) {
	c := auth.ClaimsFromContext(ctx)
	return &pb.HelloResponse{Message: "hello, " + req.GetName(), Subject: c.Subject()}, nil
}

func (g *greeterImpl) Admin(ctx context.Context, req *pb.AdminRequest) (*pb.AdminResponse, error) {
	c := auth.ClaimsFromContext(ctx)
	return &pb.AdminResponse{Result: "admin " + req.GetAction() + " by " + c.Subject()}, nil
}

func startServer(t *testing.T, cfg server.Config) (pb.GreeterClient, func()) {
	t.Helper()
	srvOpts, closer, err := server.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := grpc.NewServer(srvOpts...)
	pb.RegisterGreeterServer(s, &greeterImpl{})
	go func() { _ = s.Serve(lis) }()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	return pb.NewGreeterClient(conn), func() {
		_ = conn.Close()
		s.GracefulStop()
		_ = lis.Close()
		_ = closer.Close()
	}
}

func ctxWithToken(parent context.Context, token string) context.Context {
	if token == "" {
		return parent
	}
	return metadata.AppendToOutgoingContext(parent, "authorization", "Bearer "+token)
}

func adminPolicy(_ context.Context, _ string, c *auth.Claims) error {
	if !c.HasStringInSlice("urn:greeter:permissions", "greeter:admin") {
		return auth.Forbidden("missing permission greeter:admin")
	}
	return nil
}

func TestGreeter_AuthEnabled_PolicyMatrix(t *testing.T) {
	now := time.Now().Add(time.Hour).Unix()
	intr := &fakeIntrospector{tokens: map[string]map[string]any{
		"alice-tok": {
			"active": true, "sub": "alice", "exp": float64(now),
			"urn:greeter:permissions": []any{"greeter:user"},
		},
		"admin-tok": {
			"active": true, "sub": "root", "exp": float64(now),
			"urn:greeter:permissions": []any{"greeter:user", "greeter:admin"},
		},
	}}

	client, stop := startServer(t, server.Config{
		RequireAuth:  true,
		Introspector: intr,
		PublicMethods: []string{
			methodHealthz,
		},
		Policies: map[string][]auth.PolicyFunc{
			methodHello: nil,
			methodAdmin: {adminPolicy},
		},
	})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Healthz — public, no token needed
	if _, err := client.Healthz(ctx, &pb.HealthzRequest{}); err != nil {
		t.Fatalf("Healthz: %v", err)
	}

	// Hello — anonymous → Unauthenticated
	_, err := client.Hello(ctx, &pb.HelloRequest{Name: "anon"})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("Hello anon: want Unauthenticated, got %v", err)
	}

	// Hello — alice → success, claims propagated
	resp, err := client.Hello(ctxWithToken(ctx, "alice-tok"), &pb.HelloRequest{Name: "alice"})
	if err != nil {
		t.Fatalf("Hello alice: %v", err)
	}
	if resp.GetSubject() != "alice" {
		t.Fatalf("Hello alice: subject not propagated, got %q", resp.GetSubject())
	}

	// Admin — alice (no admin role) → PermissionDenied
	_, err = client.Admin(ctxWithToken(ctx, "alice-tok"), &pb.AdminRequest{Action: "rotate"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("Admin alice: want PermissionDenied, got %v", err)
	}

	// Admin — root (has admin) → OK
	adminResp, err := client.Admin(ctxWithToken(ctx, "admin-tok"), &pb.AdminRequest{Action: "rotate"})
	if err != nil {
		t.Fatalf("Admin root: %v", err)
	}
	if adminResp.GetResult() == "" {
		t.Fatal("Admin root: empty result")
	}

	// Admin — bogus token → Unauthenticated
	_, err = client.Admin(ctxWithToken(ctx, "nope"), &pb.AdminRequest{Action: "x"})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("Admin bogus: want Unauthenticated, got %v", err)
	}
}

func TestGreeter_AuthDisabled_AllAllowed(t *testing.T) {
	client, stop := startServer(t, server.Config{RequireAuth: false})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := client.Healthz(ctx, &pb.HealthzRequest{}); err != nil {
		t.Fatal(err)
	}
	resp, err := client.Hello(ctx, &pb.HelloRequest{Name: "anon"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetSubject() != "" {
		t.Fatalf("disabled mode should produce empty subject, got %q", resp.GetSubject())
	}
	if _, err := client.Admin(ctx, &pb.AdminRequest{Action: "x"}); err != nil {
		t.Fatalf("Admin in disabled mode should pass: %v", err)
	}
}
