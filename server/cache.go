package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	auth "github.com/agile-crypto/zitadel-grpc-auth"
	"golang.org/x/sync/singleflight"
)

// cachedEntry is one introspection result in the cache. We cache both
// positive (active=true with claims) and negative (active=false, err set)
// outcomes for the same TTL — caching negatives avoids hammering Zitadel
// with repeated bad tokens.
type cachedEntry struct {
	claims    *auth.Claims
	err       error // non-nil for negative entries (e.g. wraps ErrUnauthenticated)
	expiresAt time.Time
}

// introspectionCache is an in-memory, TTL-bounded, LRU-evicted cache of
// introspection results, with singleflight stampede protection so that N
// concurrent requests for the same uncached token result in exactly one
// upstream introspection call.
//
// The implementation deliberately keeps the dependency surface minimal: a
// plain map under a sync.Mutex with capped size + lazy expiry (the read
// path also deletes expired entries, so an RWMutex would not be safe).
// For the expected working-set sizes (≤10k entries) this is comfortably faster
// than the round-trip to Zitadel that it elides, and avoids pulling in
// hashicorp/golang-lru as a dependency. If profiling shows hot-spotting
// here in the future, swapping the backing store for an expirable LRU is a
// drop-in replacement behind this type.
type introspectionCache struct {
	ttl     time.Duration
	maxSize int
	mu      sync.Mutex
	entries map[string]*cachedEntry // key = sha256(token) hex
	order   []string                // FIFO-ish eviction order; cheap & predictable
	sf      singleflight.Group
}

// newCache returns a cache. ttl<=0 or maxSize<=0 disables caching: lookups
// always miss and stores are no-ops. The singleflight is still used so that
// a stampede of concurrent identical tokens results in one upstream call
// even with caching disabled.
func newCache(ttl time.Duration, maxSize int) *introspectionCache {
	return &introspectionCache{
		ttl:     ttl,
		maxSize: maxSize,
		entries: make(map[string]*cachedEntry),
	}
}

// disabled reports whether caching is off.
func (c *introspectionCache) disabled() bool { return c.ttl <= 0 || c.maxSize <= 0 }

// hashToken returns a SHA-256 hex digest of the token. We never use the raw
// token as a map key — that would keep token bytes in memory longer than
// necessary and risks them appearing in profiles or panic dumps.
func hashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

// get returns a non-expired entry, or (nil, false).
func (c *introspectionCache) get(key string, now time.Time) (*cachedEntry, bool) {
	if c.disabled() {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if now.After(e.expiresAt) {
		delete(c.entries, key)
		// note: order slice is cleaned lazily on next put; cost is bounded
		return nil, false
	}
	return e, true
}

// put stores an entry, evicting the oldest if at capacity.
func (c *introspectionCache) put(key string, e *cachedEntry) {
	if c.disabled() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[key]; !exists {
		if len(c.entries) >= c.maxSize {
			c.evictOldestLocked()
		}
		c.order = append(c.order, key)
	}
	c.entries[key] = e
}

// evictOldestLocked drops the oldest live entry. Must be called with c.mu held.
func (c *introspectionCache) evictOldestLocked() {
	for len(c.order) > 0 {
		k := c.order[0]
		c.order = c.order[1:]
		if _, ok := c.entries[k]; ok {
			delete(c.entries, k)
			return
		}
		// stale order entry from a lazy-expired key; keep walking
	}
}

// boundTTL returns the actual TTL for a freshly-introspected token: the
// minimum of the configured TTL and the token's own remaining lifetime. A
// zero exp (introspector didn't supply one) falls back to the configured
// TTL alone.
func (c *introspectionCache) boundTTL(now, exp time.Time) time.Duration {
	if exp.IsZero() {
		return c.ttl
	}
	remaining := exp.Sub(now)
	if remaining <= 0 {
		return 0
	}
	if remaining < c.ttl {
		return remaining
	}
	return c.ttl
}

// transportErrorTTL bounds how long a transport-level introspection failure
// (timeout, 5xx, network error) is cached before we retry. It is intentionally
// short so a transient Zitadel blip self-heals quickly, but long enough to
// stop a single caller's retry loop from converting a token-flood DoS into
// an upstream-flood DoS. See [F5] in the security audit.
const transportErrorTTL = 1 * time.Second

// resolve returns claims for the given token, going through the cache and
// singleflight. The introspector is called at most once per (token, in-flight
// window). On error from the introspector, the error is returned to the
// caller; auth-level negatives are cached for the configured TTL, and
// transport-level negatives are cached for [transportErrorTTL] to prevent
// a single attacker (or a thrashing upstream) from amplifying load on
// Zitadel.
func (c *introspectionCache) resolve(ctx context.Context, token string, intr Introspector) (*auth.Claims, error) {
	key := hashToken(token)
	now := time.Now()
	if e, ok := c.get(key, now); ok {
		return e.claims, e.err
	}

	v, err, _ := c.sf.Do(key, func() (any, error) {
		// Re-check the cache inside the singleflight: another caller may
		// have already populated it while we were queued.
		now := time.Now()
		if e, ok := c.get(key, now); ok {
			return e, nil
		}
		claims, exp, err := intr.Introspect(ctx, token)
		if err != nil {
			if c.disabled() {
				return &cachedEntry{claims: claims, err: err}, nil
			}
			ttl := c.ttl
			if !auth.IsUnauthenticated(err) {
				// Transport / unexpected errors get a much shorter TTL
				// so the cache doesn't pin a stale failure once Zitadel
				// recovers, but still elides a tight retry loop.
				ttl = transportErrorTTL
				if c.ttl > 0 && c.ttl < ttl {
					ttl = c.ttl
				}
			}
			c.put(key, &cachedEntry{
				claims:    claims,
				err:       err,
				expiresAt: now.Add(ttl),
			})
			return &cachedEntry{claims: claims, err: err}, nil
		}
		ttl := c.boundTTL(now, exp)
		if ttl > 0 {
			c.put(key, &cachedEntry{
				claims:    claims,
				expiresAt: now.Add(ttl),
			})
		}
		return &cachedEntry{claims: claims}, nil
	})
	if err != nil {
		// singleflight only surfaces errors the inner func returns; we
		// always return nil from inner so this branch is unreachable in
		// practice, but kept for safety.
		return nil, err
	}
	e := v.(*cachedEntry)
	return e.claims, e.err
}

// Close releases cache state. Reserved for forward compatibility (no-op today).
func (c *introspectionCache) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = nil
	c.order = nil
	return nil
}
