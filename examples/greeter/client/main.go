// greeter-client is a runnable example demonstrating zitadel-grpc-auth on
// the client side. It dials the example greeter server, optionally
// attaching a Zitadel-issued bearer token via the OAuth2
// client_credentials grant.
//
// Run with auth disabled (matches `greeter-server` in dev mode):
//
//	go run ./examples/greeter/client -op hello
//
// Run with auth enabled:
//
//	AUTH_ENABLED=true \
//	ZITADEL_ISSUER=http://localhost:8080 \
//	CLIENT_ID=<service-user-client-id> \
//	CLIENT_SECRET=<service-user-client-secret> \
//	PROJECT_ID=<zitadel-project-id> \
//	go run ./examples/greeter/client -op admin -name alice
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/agile-crypto/zitadel-grpc-auth/client"
	pb "github.com/agile-crypto/zitadel-grpc-auth/examples/greeter/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	addr := flag.String("addr", "localhost:50061", "greeter server address")
	op := flag.String("op", "hello", "operation: healthz | hello | admin")
	name := flag.String("name", "world", "name for hello/action for admin")
	flag.Parse()

	cfg := loadEnv()

	// Use a long-lived context for the token source so that token refreshes
	// during the program's lifetime are not cancelled by per-RPC deadlines.
	tsCtx, cancelTS := context.WithCancel(context.Background())
	defer cancelTS()

	authOpts, closer, err := client.New(tsCtx, client.Config{
		AttachToken:  cfg.attachToken,
		Issuer:       cfg.issuer,
		ClientID:     cfg.clientID,
		ClientSecret: cfg.clientSecret,
		Scopes: []string{
			"openid",
			"urn:zitadel:iam:org:project:id:" + cfg.projectID + ":aud",
		},
	})
	if err != nil {
		log.Fatalf("client.New: %v", err)
	}
	defer closer.Close()

	dialOpts := append([]grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}, authOpts...)
	conn, err := grpc.NewClient(*addr, dialOpts...)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	g := pb.NewGreeterClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	switch *op {
	case "healthz":
		resp, err := g.Healthz(ctx, &pb.HealthzRequest{})
		check(err)
		fmt.Printf("Healthz: %s\n", resp.GetStatus())

	case "hello":
		resp, err := g.Hello(ctx, &pb.HelloRequest{Name: *name})
		check(err)
		fmt.Printf("Hello: %s (sub=%q)\n", resp.GetMessage(), resp.GetSubject())

	case "admin":
		resp, err := g.Admin(ctx, &pb.AdminRequest{Action: *name})
		check(err)
		fmt.Printf("Admin: %s\n", resp.GetResult())

	default:
		log.Fatalf("unknown op %q (want healthz | hello | admin)", *op)
	}
}

func check(err error) {
	if err != nil {
		log.Fatalf("RPC failed: %v", err)
	}
}

type envConfig struct {
	attachToken  bool
	issuer       string
	clientID     string
	clientSecret string
	projectID    string
}

func loadEnv() envConfig {
	return envConfig{
		attachToken:  os.Getenv("AUTH_ENABLED") == "true",
		issuer:       os.Getenv("ZITADEL_ISSUER"),
		clientID:     os.Getenv("CLIENT_ID"),
		clientSecret: os.Getenv("CLIENT_SECRET"),
		projectID:    os.Getenv("PROJECT_ID"),
	}
}
