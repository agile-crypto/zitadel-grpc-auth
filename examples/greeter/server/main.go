// greeter-server is a runnable example demonstrating zitadel-grpc-auth on
// the server side. It registers three RPCs:
//
//	Healthz : public, bypasses auth
//	Hello   : authenticated only (any valid token)
//	Admin   : requires the "greeter:admin" permission under "urn:greeter:permissions"
//
// The custom claim is produced by the Pre-Userinfo action that
// `admin.Bootstrap` (used by scripts/setup-sdk) wires into Zitadel — it
// flattens the user's project-role grants into a deduplicated string
// array under "<namespace>:permissions" (here `urn:greeter:permissions`).
//
// Run it with auth disabled (no Zitadel needed):
//
//	go run ./examples/greeter/server
//
// Run it with auth enabled against a Zitadel instance:
//
//	AUTH_ENABLED=true \
//	ZITADEL_ISSUER=http://localhost:8080 \
//	INTROSPECT_ID=<api-app-client-id> \
//	INTROSPECT_SECRET=<api-app-client-secret> \
//	go run ./examples/greeter/server
//
// The example deliberately reads its own configuration from the environment
// — the zitadel-grpc-auth module itself never reads env. The application
// owns config sourcing.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	auth "github.ibm.com/citius/zitadel-grpc-auth"
	pb "github.ibm.com/citius/zitadel-grpc-auth/examples/greeter/pb"
	"github.ibm.com/citius/zitadel-grpc-auth/server"
	"google.golang.org/grpc"
)

// Fully-qualified gRPC method names. Newer protoc-gen-go-grpc emits these
// as `pb.Greeter_<RPC>_FullMethodName` constants; we declare them locally
// so the example builds against any recent version.
const (
	methodHealthz = "/greeter.v1.Greeter/Healthz"
	methodHello   = "/greeter.v1.Greeter/Hello"
	methodAdmin   = "/greeter.v1.Greeter/Admin"
)

func main() {
	addr := flag.String("addr", ":50061", "listen address")
	flag.Parse()

	cfg := loadConfigFromEnv()

	requireAdmin := func(_ context.Context, _ string, c *auth.Claims) error {
		if !c.HasStringInSlice("urn:greeter:permissions", "greeter:admin") {
			return auth.Forbidden("missing permission greeter:admin")
		}
		return nil
	}

	srvOpts, closer, err := server.New(server.Config{
		RequireAuth:               cfg.requireAuth,
		Issuer:                    cfg.issuer,
		IntrospectionClientID:     cfg.introspectID,
		IntrospectionClientSecret: cfg.introspectSecret,
		Insecure:                  cfg.insecure,
		CacheTTL:                  cfg.cacheTTL,
		CacheMaxEntries:           1000,
		PublicMethods: []string{
			methodHealthz,
		},
		Policies: map[string][]auth.PolicyFunc{
			methodHello: nil, // auth-only
			methodAdmin: {requireAdmin},
		},
	})
	if err != nil {
		log.Fatalf("server.New: %v", err)
	}
	defer closer.Close()

	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	s := grpc.NewServer(srvOpts...)
	pb.RegisterGreeterServer(s, &greeterImpl{})

	mode := "AUTH ENABLED"
	if !cfg.requireAuth {
		mode = "AUTH DISABLED (dev mode)"
	}
	log.Printf("greeter listening on %s — %s", lis.Addr(), mode)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

type greeterImpl struct {
	pb.UnimplementedGreeterServer
}

func (g *greeterImpl) Healthz(_ context.Context, _ *pb.HealthzRequest) (*pb.HealthzResponse, error) {
	return &pb.HealthzResponse{Status: "ok"}, nil
}

func (g *greeterImpl) Hello(ctx context.Context, req *pb.HelloRequest) (*pb.HelloResponse, error) {
	c := auth.ClaimsFromContext(ctx) // safe to call even when auth is disabled
	return &pb.HelloResponse{
		Message: fmt.Sprintf("hello, %s", req.GetName()),
		Subject: c.Subject(), // "" when auth is disabled
	}, nil
}

func (g *greeterImpl) Admin(ctx context.Context, req *pb.AdminRequest) (*pb.AdminResponse, error) {
	c := auth.ClaimsFromContext(ctx)
	return &pb.AdminResponse{
		Result: fmt.Sprintf("admin %q performed by %s", req.GetAction(), c.Subject()),
	}, nil
}

type envConfig struct {
	requireAuth      bool
	issuer           string
	introspectID     string
	introspectSecret string
	insecure         bool
	cacheTTL         time.Duration
}

func loadConfigFromEnv() envConfig {
	c := envConfig{
		requireAuth:      os.Getenv("AUTH_ENABLED") == "true",
		issuer:           os.Getenv("ZITADEL_ISSUER"),
		introspectID:     os.Getenv("INTROSPECT_ID"),
		introspectSecret: os.Getenv("INTROSPECT_SECRET"),
		insecure:         os.Getenv("ZITADEL_INSECURE") != "false", // default true for local dev
		cacheTTL:         30 * time.Second,
	}
	if v := os.Getenv("CACHE_TTL_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.cacheTTL = time.Duration(n) * time.Second
		}
	}
	return c
}
