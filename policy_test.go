package auth

import (
	"context"
	"errors"
	"testing"
)

func TestAll_ShortCircuitAndOrder(t *testing.T) {
	ctx := context.Background()
	calls := 0
	ok := func(_ context.Context, _ string, _ *Claims) error { calls++; return nil }
	bad := func(_ context.Context, _ string, _ *Claims) error { calls++; return Forbidden("nope") }

	if err := All(ok, ok, ok)(ctx, "/m", nil); err != nil || calls != 3 {
		t.Fatalf("All should call every policy on success: err=%v calls=%d", err, calls)
	}

	calls = 0
	if err := All(ok, bad, ok)(ctx, "/m", nil); !IsForbidden(err) || calls != 2 {
		t.Fatalf("All should short-circuit on first error: err=%v calls=%d", err, calls)
	}

	if err := All()(ctx, "/m", nil); err != nil {
		t.Fatal("All() with no policies should allow")
	}
}

func TestAny_AllowsOnFirstSuccess(t *testing.T) {
	ctx := context.Background()
	bad := func(_ context.Context, _ string, _ *Claims) error { return Forbidden("nope") }
	ok := func(_ context.Context, _ string, _ *Claims) error { return nil }

	if err := Any(bad, ok, bad)(ctx, "/m", nil); err != nil {
		t.Fatalf("Any should allow if any succeeds: %v", err)
	}
	if err := Any(bad, bad)(ctx, "/m", nil); !IsForbidden(err) {
		t.Fatalf("Any should return last error if all fail: %v", err)
	}
	if err := Any()(ctx, "/m", nil); !IsForbidden(err) {
		t.Fatalf("Any() with no policies should deny: %v", err)
	}
}

func TestAll_NilPoliciesSkipped(t *testing.T) {
	ctx := context.Background()
	if err := All(nil, nil)(ctx, "/m", nil); err != nil {
		t.Fatalf("nil policies should be skipped: %v", err)
	}
}

func TestAuthorizeGlobPattern(t *testing.T) {
	cases := []struct {
		name        string
		resource    string
		allow, deny []string
		wantErr     bool
	}{
		{"empty allow + empty deny → allow", "x", nil, nil, false},
		{"wildcard allow", "anything", []string{"*"}, nil, false},
		{"prefix match", "payments-2026", []string{"payments-*"}, nil, false},
		{"prefix non-match", "secrets-prod", []string{"payments-*"}, nil, true},
		{"suffix match", "billing-prod", []string{"*-prod"}, nil, false},
		{"substring match", "foo-bar-baz", []string{"*bar*"}, nil, false},
		{"deny wins over allow", "secrets-prod", []string{"*"}, []string{"secrets-*"}, true},
		{"exact match required", "key1", []string{"key1"}, nil, false},
		{"exact non-match", "key2", []string{"key1"}, nil, true},
		{"empty allow but deny matches", "secrets-prod", nil, []string{"secrets-*"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := AuthorizeGlobPattern(tc.resource, tc.allow, tc.deny)
			if tc.wantErr && err == nil {
				t.Fatalf("expected forbidden, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected allow, got %v", err)
			}
			if tc.wantErr && !IsForbidden(err) {
				t.Fatalf("error must wrap ErrForbidden: %v", err)
			}
		})
	}
}

func TestAuthorizeGlobPatternStrict(t *testing.T) {
	cases := []struct {
		name        string
		resource    string
		allow, deny []string
		wantErr     bool
	}{
		{"empty allow → deny (default-deny)", "x", nil, nil, true},
		{"wildcard allow", "anything", []string{"*"}, nil, false},
		{"deny wins over allow", "secrets-prod", []string{"*"}, []string{"secrets-*"}, true},
		{"matches allow pattern", "payments-2026", []string{"payments-*"}, nil, false},
		{"non-match allow", "billing", []string{"payments-*"}, nil, true},
		{"empty allow + non-matching deny still denies", "x", nil, []string{"never-matches-*"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := AuthorizeGlobPatternStrict(tc.resource, tc.allow, tc.deny)
			if tc.wantErr && !IsForbidden(err) {
				t.Fatalf("expected ErrForbidden, got %v", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected allow, got %v", err)
			}
		})
	}
}

func TestAny_ReturnsLastError(t *testing.T) {
	ctx := context.Background()
	first := errors.New("first")
	second := errors.New("second")
	p1 := func(_ context.Context, _ string, _ *Claims) error { return first }
	p2 := func(_ context.Context, _ string, _ *Claims) error { return second }
	if err := Any(p1, p2)(ctx, "/m", nil); err != second {
		t.Fatalf("Any should return last error, got %v", err)
	}
}
