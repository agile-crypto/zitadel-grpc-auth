package server

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	auth "github.ibm.com/citius/zitadel-grpc-auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// streamingHealthSvc implements the streaming Watch RPC and records the
// subject from claims in handler context.
type streamingHealthSvc struct {
	healthpb.UnimplementedHealthServer
	lastSub atomic.Value
}

func (s *streamingHealthSvc) Watch(req *healthpb.HealthCheckRequest, stream healthpb.Health_WatchServer) error {
	c := auth.ClaimsFromContext(stream.Context())
	if c != nil {
		s.lastSub.Store(c.Subject())
	} else {
		s.lastSub.Store("")
	}
	return stream.Send(&healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING})
}

func startStreamServer(t *testing.T, srvOpts []grpc.ServerOption) (string, *streamingHealthSvc, func()) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := grpc.NewServer(srvOpts...)
	svc := &streamingHealthSvc{}
	healthpb.RegisterHealthServer(s, svc)
	go func() { _ = s.Serve(lis) }()
	return lis.Addr().String(), svc, func() { s.GracefulStop(); _ = lis.Close() }
}

func TestServer_StreamInterceptor_PropagatesClaims(t *testing.T) {
	intr := &fakeIntrospector{respond: func(string) (*auth.Claims, time.Time, error) {
		return aliceClaims(), time.Now().Add(time.Hour), nil
	}}
	srvOpts, closer, _ := New(Config{
		RequireAuth:  true,
		Introspector: intr,
		Policies: map[string][]auth.PolicyFunc{
			"/grpc.health.v1.Health/Watch": nil,
		},
	})
	defer closer.Close()
	addr, svc, stop := startStreamServer(t, srvOpts)
	defer stop()

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer tok")

	stream, err := healthpb.NewHealthClient(conn).Watch(ctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatal(err)
	}
	if got, _ := svc.lastSub.Load().(string); got != "alice" {
		t.Fatalf("stream handler did not see claims, got sub=%q", got)
	}
}

func TestServer_StreamInterceptor_DeniedBeforeOpen(t *testing.T) {
	intr := &fakeIntrospector{respond: func(string) (*auth.Claims, time.Time, error) {
		return aliceClaims(), time.Now().Add(time.Hour), nil
	}}
	srvOpts, closer, _ := New(Config{
		RequireAuth:  true,
		Introspector: intr,
		// no Policies entry → default deny
	})
	defer closer.Close()
	addr, _, stop := startStreamServer(t, srvOpts)
	defer stop()

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer tok")
	stream, err := healthpb.NewHealthClient(conn).Watch(ctx, &healthpb.HealthCheckRequest{})
	// the stream RPC may return at open or only on first Recv depending on
	// server timing — handle both.
	if err == nil {
		_, err = stream.Recv()
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
}

func TestCache_LRUEviction(t *testing.T) {
	c := newCache(time.Hour, 2)
	now := time.Now()
	mk := func(s string) *cachedEntry {
		return &cachedEntry{
			claims:    auth.NewClaims(map[string]any{"sub": s}),
			expiresAt: now.Add(time.Hour),
		}
	}
	c.put("k1", mk("a"))
	c.put("k2", mk("b"))
	c.put("k3", mk("c")) // should evict k1 (oldest)

	if _, ok := c.get("k1", now); ok {
		t.Fatal("k1 should have been evicted")
	}
	if _, ok := c.get("k2", now); !ok {
		t.Fatal("k2 should still be present")
	}
	if _, ok := c.get("k3", now); !ok {
		t.Fatal("k3 should be present")
	}
}

func TestCache_LazyExpiry(t *testing.T) {
	c := newCache(time.Hour, 10)
	now := time.Now()
	c.put("k1", &cachedEntry{
		claims:    auth.NewClaims(map[string]any{}),
		expiresAt: now.Add(-time.Second), // already expired
	})
	if _, ok := c.get("k1", now); ok {
		t.Fatal("expired entry should not be returned")
	}
}

func TestCache_Disabled_NoOp(t *testing.T) {
	c := newCache(0, 0)
	c.put("k", &cachedEntry{claims: auth.NewClaims(map[string]any{}), expiresAt: time.Now().Add(time.Hour)})
	if _, ok := c.get("k", time.Now()); ok {
		t.Fatal("disabled cache should always miss")
	}
}
