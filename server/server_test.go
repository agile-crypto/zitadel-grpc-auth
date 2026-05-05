package server

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.ibm.com/citius/zitadel-grpc-auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// fakeIntrospector is a recordable in-memory Introspector for tests. The
// callback can simulate latency, errors, or canned responses.
type fakeIntrospector struct {
	mu       sync.Mutex
	calls    atomic.Int32
	respond  func(token string) (*auth.Claims, time.Time, error)
	gateOpen chan struct{} // optional: closed to release a held call
}

func (f *fakeIntrospector) Introspect(ctx context.Context, token string) (*auth.Claims, time.Time, error) {
	f.calls.Add(1)
	if f.gateOpen != nil {
		select {
		case <-f.gateOpen:
		case <-ctx.Done():
			return nil, time.Time{}, ctx.Err()
		}
	}
	f.mu.Lock()
	r := f.respond
	f.mu.Unlock()
	return r(token)
}

// claimsHealthSvc returns the claims it sees in handler context inside the
// status field, so tests can assert end-to-end propagation.
type claimsHealthSvc struct {
	healthpb.UnimplementedHealthServer
	lastSub atomic.Value // string
}

func (s *claimsHealthSvc) Check(ctx context.Context, req *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	c := auth.ClaimsFromContext(ctx)
	if c != nil {
		s.lastSub.Store(c.Subject())
	} else {
		s.lastSub.Store("")
	}
	return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}, nil
}

func startServer(t *testing.T, srvOpts []grpc.ServerOption) (string, *claimsHealthSvc, func()) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := grpc.NewServer(srvOpts...)
	svc := &claimsHealthSvc{}
	healthpb.RegisterHealthServer(s, svc)
	// also register the upstream health for completeness; not used in assertions
	_ = health.NewServer
	go func() { _ = s.Serve(lis) }()
	return lis.Addr().String(), svc, func() { s.GracefulStop(); _ = lis.Close() }
}

func dial(t *testing.T, addr string) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func callCheckWithToken(t *testing.T, conn *grpc.ClientConn, token string) error {
	t.Helper()
	ctx := context.Background()
	if token != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	return err
}

func aliceClaims() *auth.Claims {
	return auth.NewClaims(map[string]any{
		"active":                  true,
		"sub":                     "alice",
		"urn:citius:permissions": []any{"citius:read"},
	})
}

func TestServer_RequireAuthFalse_PassesThrough(t *testing.T) {
	srvOpts, closer, err := New(Config{RequireAuth: false})
	if err != nil {
		t.Fatal(err)
	}
	defer closer.Close()
	addr, svc, stop := startServer(t, srvOpts)
	defer stop()

	conn := dial(t, addr)
	defer conn.Close()
	if err := callCheckWithToken(t, conn, ""); err != nil {
		t.Fatalf("disabled mode should accept unauthenticated calls: %v", err)
	}
	if got, _ := svc.lastSub.Load().(string); got != "" {
		t.Fatalf("expected empty subject in disabled mode, got %q", got)
	}
}

func TestServer_MissingBearer_Unauthenticated(t *testing.T) {
	intr := &fakeIntrospector{respond: func(string) (*auth.Claims, time.Time, error) { return aliceClaims(), time.Time{}, nil }}
	srvOpts, closer, _ := New(Config{
		RequireAuth:  true,
		Introspector: intr,
		Policies: map[string][]auth.PolicyFunc{
			"/grpc.health.v1.Health/Check": nil, // empty slice = auth-only
		},
	})
	defer closer.Close()
	addr, _, stop := startServer(t, srvOpts)
	defer stop()
	conn := dial(t, addr)
	defer conn.Close()

	err := callCheckWithToken(t, conn, "")
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", err)
	}
	if intr.calls.Load() != 0 {
		t.Fatalf("introspector should not be called when bearer is missing")
	}
}

func TestServer_DefaultDeny_MethodNotInPolicies(t *testing.T) {
	intr := &fakeIntrospector{respond: func(string) (*auth.Claims, time.Time, error) { return aliceClaims(), time.Time{}, nil }}
	srvOpts, closer, _ := New(Config{
		RequireAuth:  true,
		Introspector: intr,
		Policies:     map[string][]auth.PolicyFunc{}, // method not registered
	})
	defer closer.Close()
	addr, _, stop := startServer(t, srvOpts)
	defer stop()
	conn := dial(t, addr)
	defer conn.Close()

	err := callCheckWithToken(t, conn, "valid-token")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied (default deny), got %v", err)
	}
}

func TestServer_PolicySliceAND_AllMustPass(t *testing.T) {
	intr := &fakeIntrospector{respond: func(string) (*auth.Claims, time.Time, error) { return aliceClaims(), time.Time{}, nil }}
	allow := func(_ context.Context, _ string, _ *auth.Claims) error { return nil }
	deny := func(_ context.Context, _ string, _ *auth.Claims) error { return auth.Forbidden("nope") }

	t.Run("all pass → handler runs", func(t *testing.T) {
		srvOpts, closer, _ := New(Config{
			RequireAuth:  true,
			Introspector: intr,
			Policies: map[string][]auth.PolicyFunc{
				"/grpc.health.v1.Health/Check": {allow, allow},
			},
		})
		defer closer.Close()
		addr, svc, stop := startServer(t, srvOpts)
		defer stop()
		conn := dial(t, addr)
		defer conn.Close()
		if err := callCheckWithToken(t, conn, "tok"); err != nil {
			t.Fatalf("expected success, got %v", err)
		}
		if got, _ := svc.lastSub.Load().(string); got != "alice" {
			t.Fatalf("claims not propagated to handler: %q", got)
		}
	})

	t.Run("one fails → PermissionDenied", func(t *testing.T) {
		srvOpts, closer, _ := New(Config{
			RequireAuth:  true,
			Introspector: intr,
			Policies: map[string][]auth.PolicyFunc{
				"/grpc.health.v1.Health/Check": {allow, deny, allow},
			},
		})
		defer closer.Close()
		addr, _, stop := startServer(t, srvOpts)
		defer stop()
		conn := dial(t, addr)
		defer conn.Close()
		err := callCheckWithToken(t, conn, "tok")
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("expected PermissionDenied, got %v", err)
		}
	})
}

func TestServer_PublicMethod_BypassesAuth(t *testing.T) {
	intr := &fakeIntrospector{respond: func(string) (*auth.Claims, time.Time, error) {
		t.Fatal("introspector must not be called for public methods")
		return nil, time.Time{}, nil
	}}
	srvOpts, closer, _ := New(Config{
		RequireAuth:   true,
		Introspector:  intr,
		PublicMethods: []string{"/grpc.health.v1.Health/Check"},
	})
	defer closer.Close()
	addr, svc, stop := startServer(t, srvOpts)
	defer stop()
	conn := dial(t, addr)
	defer conn.Close()
	if err := callCheckWithToken(t, conn, ""); err != nil {
		t.Fatalf("public method should pass without token: %v", err)
	}
	if got, _ := svc.lastSub.Load().(string); got != "" {
		t.Fatalf("public method should run with empty claims, got sub=%q", got)
	}
}

func TestServer_InactiveToken_Unauthenticated(t *testing.T) {
	inactive := auth.NewClaims(map[string]any{"active": false})
	intr := &fakeIntrospector{respond: func(string) (*auth.Claims, time.Time, error) {
		return inactive, time.Time{}, auth.Unauthenticated("token not active")
	}}
	srvOpts, closer, _ := New(Config{
		RequireAuth:  true,
		Introspector: intr,
		Policies:     map[string][]auth.PolicyFunc{"/grpc.health.v1.Health/Check": nil},
	})
	defer closer.Close()
	addr, _, stop := startServer(t, srvOpts)
	defer stop()
	conn := dial(t, addr)
	defer conn.Close()
	err := callCheckWithToken(t, conn, "tok")
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", err)
	}
}

func TestServer_CacheHit_AvoidsIntrospect(t *testing.T) {
	intr := &fakeIntrospector{respond: func(string) (*auth.Claims, time.Time, error) {
		return aliceClaims(), time.Now().Add(time.Hour), nil
	}}
	srvOpts, closer, _ := New(Config{
		RequireAuth:     true,
		Introspector:    intr,
		CacheTTL:        time.Minute,
		CacheMaxEntries: 100,
		Policies:        map[string][]auth.PolicyFunc{"/grpc.health.v1.Health/Check": nil},
	})
	defer closer.Close()
	addr, _, stop := startServer(t, srvOpts)
	defer stop()
	conn := dial(t, addr)
	defer conn.Close()
	for i := 0; i < 5; i++ {
		if err := callCheckWithToken(t, conn, "same-token"); err != nil {
			t.Fatal(err)
		}
	}
	if intr.calls.Load() != 1 {
		t.Fatalf("expected 1 introspection call, got %d", intr.calls.Load())
	}
}

func TestServer_NegativeCaching(t *testing.T) {
	inactive := auth.NewClaims(map[string]any{"active": false})
	intr := &fakeIntrospector{respond: func(string) (*auth.Claims, time.Time, error) {
		return inactive, time.Time{}, auth.Unauthenticated("token not active")
	}}
	srvOpts, closer, _ := New(Config{
		RequireAuth:     true,
		Introspector:    intr,
		CacheTTL:        time.Minute,
		CacheMaxEntries: 100,
		Policies:        map[string][]auth.PolicyFunc{"/grpc.health.v1.Health/Check": nil},
	})
	defer closer.Close()
	addr, _, stop := startServer(t, srvOpts)
	defer stop()
	conn := dial(t, addr)
	defer conn.Close()
	for i := 0; i < 5; i++ {
		_ = callCheckWithToken(t, conn, "bad-token")
	}
	if intr.calls.Load() != 1 {
		t.Fatalf("expected negative caching to elide repeats, got %d", intr.calls.Load())
	}
}

func TestServer_Singleflight_CollapsesConcurrent(t *testing.T) {
	gate := make(chan struct{})
	intr := &fakeIntrospector{
		gateOpen: gate,
		respond: func(string) (*auth.Claims, time.Time, error) {
			return aliceClaims(), time.Now().Add(time.Hour), nil
		},
	}
	srvOpts, closer, _ := New(Config{
		RequireAuth:     true,
		Introspector:    intr,
		CacheTTL:        time.Minute,
		CacheMaxEntries: 100,
		Policies:        map[string][]auth.PolicyFunc{"/grpc.health.v1.Health/Check": nil},
	})
	defer closer.Close()
	addr, _, stop := startServer(t, srvOpts)
	defer stop()
	conn := dial(t, addr)
	defer conn.Close()

	var wg sync.WaitGroup
	const N = 25
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			_ = callCheckWithToken(t, conn, "stampede-token")
		}()
	}
	// Give all goroutines time to enter introspect()
	time.Sleep(100 * time.Millisecond)
	close(gate)
	wg.Wait()

	if got := intr.calls.Load(); got != 1 {
		t.Fatalf("singleflight should collapse %d concurrent calls into 1, got %d", N, got)
	}
}

func TestServer_CacheTTLBoundedByTokenExp(t *testing.T) {
	c := newCache(time.Hour, 10)
	now := time.Now()
	if got := c.boundTTL(now, now.Add(5*time.Minute)); got != 5*time.Minute {
		t.Fatalf("expected token exp to win, got %v", got)
	}
	if got := c.boundTTL(now, now.Add(2*time.Hour)); got != time.Hour {
		t.Fatalf("expected configured TTL to win, got %v", got)
	}
	if got := c.boundTTL(now, time.Time{}); got != time.Hour {
		t.Fatalf("zero exp should fall back to configured TTL, got %v", got)
	}
	if got := c.boundTTL(now, now.Add(-time.Second)); got != 0 {
		t.Fatalf("expired token should yield zero TTL, got %v", got)
	}
}

func TestServer_TransportError_BoundedNegativeCache(t *testing.T) {
	// A non-auth error must still be cached briefly so a hostile retry
	// loop can't amplify load on Zitadel. See cache.go transportErrorTTL.
	intr := &fakeIntrospector{respond: func(string) (*auth.Claims, time.Time, error) {
		return nil, time.Time{}, context.DeadlineExceeded
	}}
	srvOpts, closer, _ := New(Config{
		RequireAuth:     true,
		Introspector:    intr,
		CacheTTL:        time.Minute,
		CacheMaxEntries: 100,
		Policies:        map[string][]auth.PolicyFunc{"/grpc.health.v1.Health/Check": nil},
	})
	defer closer.Close()
	addr, _, stop := startServer(t, srvOpts)
	defer stop()
	conn := dial(t, addr)
	defer conn.Close()
	for i := 0; i < 5; i++ {
		_ = callCheckWithToken(t, conn, "tok-transport-err")
	}
	if got := intr.calls.Load(); got != 1 {
		t.Fatalf("expected transport error to be cached briefly (1 call), got %d", got)
	}
}

func TestServer_Validation_RequiredFields(t *testing.T) {
	_, _, err := New(Config{RequireAuth: true, Issuer: "http://x"})
	if err == nil {
		t.Fatal("expected validation error for missing IntrospectionClient*")
	}
}

func TestServer_ExpectedIssuer_Mismatch(t *testing.T) {
	intr := &fakeIntrospector{respond: func(string) (*auth.Claims, time.Time, error) {
		return auth.NewClaims(map[string]any{
			"active": true,
			"sub":    "alice",
			"iss":    "https://attacker.example.com",
		}), time.Time{}, nil
	}}
	srvOpts, closer, _ := New(Config{
		RequireAuth:    true,
		Introspector:   intr,
		ExpectedIssuer: "https://issuer.example.com",
		Policies:       map[string][]auth.PolicyFunc{"/grpc.health.v1.Health/Check": nil},
	})
	defer closer.Close()
	addr, _, stop := startServer(t, srvOpts)
	defer stop()
	conn := dial(t, addr)
	defer conn.Close()
	if err := callCheckWithToken(t, conn, "tok"); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated for bad issuer, got %v", err)
	}
}

func TestServer_ExpectedAudience_Mismatch(t *testing.T) {
	intr := &fakeIntrospector{respond: func(string) (*auth.Claims, time.Time, error) {
		return auth.NewClaims(map[string]any{
			"active": true,
			"sub":    "alice",
			"aud":    []any{"some-other-api"},
		}), time.Time{}, nil
	}}
	srvOpts, closer, _ := New(Config{
		RequireAuth:      true,
		Introspector:     intr,
		ExpectedAudience: []string{"urn:zitadel:iam:org:project:id:greeter:aud"},
		Policies:         map[string][]auth.PolicyFunc{"/grpc.health.v1.Health/Check": nil},
	})
	defer closer.Close()
	addr, _, stop := startServer(t, srvOpts)
	defer stop()
	conn := dial(t, addr)
	defer conn.Close()
	if err := callCheckWithToken(t, conn, "tok"); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated for bad audience, got %v", err)
	}
}

func TestServer_ExpectedAudience_Match(t *testing.T) {
	intr := &fakeIntrospector{respond: func(string) (*auth.Claims, time.Time, error) {
		return auth.NewClaims(map[string]any{
			"active": true,
			"sub":    "alice",
			"aud":    []any{"other", "urn:zitadel:iam:org:project:id:greeter:aud"},
		}), time.Time{}, nil
	}}
	srvOpts, closer, _ := New(Config{
		RequireAuth:      true,
		Introspector:     intr,
		ExpectedAudience: []string{"urn:zitadel:iam:org:project:id:greeter:aud"},
		Policies:         map[string][]auth.PolicyFunc{"/grpc.health.v1.Health/Check": nil},
	})
	defer closer.Close()
	addr, _, stop := startServer(t, srvOpts)
	defer stop()
	conn := dial(t, addr)
	defer conn.Close()
	if err := callCheckWithToken(t, conn, "tok"); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func TestServer_Validation_RejectsHTTPInProd(t *testing.T) {
	_, _, err := New(Config{
		RequireAuth:               true,
		Issuer:                    "http://localhost:8080",
		IntrospectionClientID:     "id",
		IntrospectionClientSecret: "secret",
		Insecure:                  false,
	})
	if err == nil {
		t.Fatal("expected error: http issuer requires Insecure=true")
	}
}
