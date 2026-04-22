package client

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
)

// fakeTokenEndpoint serves the OAuth2 client_credentials token grant.
func fakeTokenEndpoint(t *testing.T, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if r.PostForm.Get("grant_type") != "client_credentials" {
			http.Error(w, "bad grant_type", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "tok-abc-123",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
}

// authCapturingHealthSvc records the authorization header from each Check call.
type authCapturingHealthSvc struct {
	*health.Server
	last atomic.Value // string
}

func (s *authCapturingHealthSvc) Check(ctx context.Context, req *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if v := md.Get("authorization"); len(v) > 0 {
			s.last.Store(v[0])
		} else {
			s.last.Store("")
		}
	} else {
		s.last.Store("")
	}
	return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}, nil
}

func startGRPCServer(t *testing.T) (string, *authCapturingHealthSvc, func()) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := grpc.NewServer()
	svc := &authCapturingHealthSvc{Server: health.NewServer()}
	healthpb.RegisterHealthServer(s, svc)
	go func() { _ = s.Serve(lis) }()
	return lis.Addr().String(), svc, func() { s.GracefulStop(); _ = lis.Close() }
}

func TestClient_AttachToken_True_AttachesBearer(t *testing.T) {
	var tokenHits atomic.Int32
	tokenSrv := fakeTokenEndpoint(t, &tokenHits)
	defer tokenSrv.Close()

	addr, svc, stop := startGRPCServer(t)
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	authOpts, closer, err := New(ctx, Config{
		AttachToken:   true,
		Issuer:        "http://example.invalid", // overridden by TokenEndpoint
		ClientID:      "id",
		ClientSecret:  "secret",
		TokenEndpoint: tokenSrv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer closer.Close()

	conn, err := grpc.NewClient(addr, append([]grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}, authOpts...)...)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	hc := healthpb.NewHealthClient(conn)
	for i := 0; i < 3; i++ {
		if _, err := hc.Check(ctx, &healthpb.HealthCheckRequest{}); err != nil {
			t.Fatal(err)
		}
	}

	got, _ := svc.last.Load().(string)
	if !strings.HasPrefix(got, "Bearer ") {
		t.Fatalf("server did not see Bearer header, got %q", got)
	}
	if !strings.Contains(got, "tok-abc-123") {
		t.Fatalf("wrong token forwarded: %q", got)
	}
	if h := tokenHits.Load(); h != 1 {
		t.Errorf("expected token endpoint hit exactly once (cached), got %d", h)
	}
}

func TestClient_AttachToken_False_PassThrough(t *testing.T) {
	addr, svc, stop := startGRPCServer(t)
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	authOpts, closer, err := New(ctx, Config{AttachToken: false})
	if err != nil {
		t.Fatal(err)
	}
	defer closer.Close()

	conn, err := grpc.NewClient(addr, append([]grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}, authOpts...)...)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{}); err != nil {
		t.Fatal(err)
	}
	if got, _ := svc.last.Load().(string); got != "" {
		t.Fatalf("expected no auth header in disabled mode, got %q", got)
	}
}

func TestClient_AttachToken_True_RequiresFields(t *testing.T) {
	_, _, err := New(context.Background(), Config{AttachToken: true, Issuer: "http://x"})
	if err == nil {
		t.Fatal("expected validation error for missing ClientID/Secret")
	}
	if !strings.Contains(err.Error(), "ClientID") || !strings.Contains(err.Error(), "ClientSecret") {
		t.Fatalf("validation error should list missing fields, got %v", err)
	}
}
