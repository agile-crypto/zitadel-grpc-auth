package auth

import (
	"encoding/json"
	"time"
)

// Claims is a typed wrapper around an OIDC introspection response — the JSON
// object returned by Zitadel's /oauth/v2/introspect endpoint. The wrapper is
// deliberately a thin set of accessors over a map[string]any so that the
// module makes no assumptions about which custom claim names a deployment
// uses (e.g. urn:citius:permissions, urn:zitadel:iam:org:project:roles, …).
//
// A nil *Claims is safe to use: every accessor returns the zero value of its
// return type. This means policies need not nil-check before reading claims.
type Claims struct {
	raw map[string]any
}

// NewClaims constructs a Claims from a raw introspection map. The map is
// retained by reference; callers should not mutate it after construction.
func NewClaims(raw map[string]any) *Claims {
	return &Claims{raw: raw}
}

// Raw returns the underlying map. The returned map is the live backing store;
// callers should treat it as read-only.
func (c *Claims) Raw() map[string]any {
	if c == nil {
		return nil
	}
	return c.raw
}

// Active returns the standard "active" introspection claim. Returns false for
// a nil receiver or when the claim is missing or not a bool.
func (c *Claims) Active() bool {
	if c == nil {
		return false
	}
	b, _ := c.raw["active"].(bool)
	return b
}

// Subject returns the "sub" claim. Returns "" when missing or wrong type.
func (c *Claims) Subject() string { return c.String("sub") }

// Issuer returns the "iss" claim. Returns "" when missing or wrong type.
func (c *Claims) Issuer() string { return c.String("iss") }

// Username returns Zitadel's "username" claim, or "" when missing.
func (c *Claims) Username() string { return c.String("username") }

// Expiration returns the standard "exp" claim as time.Time. Returns the zero
// time when the claim is missing or not numeric.
func (c *Claims) Expiration() time.Time {
	if c == nil {
		return time.Time{}
	}
	switch v := c.raw["exp"].(type) {
	case float64:
		return time.Unix(int64(v), 0)
	case int64:
		return time.Unix(v, 0)
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return time.Unix(i, 0)
		}
	}
	return time.Time{}
}

// String returns the value at key as a string, or "" if missing or not a
// string.
func (c *Claims) String(key string) string {
	if c == nil {
		return ""
	}
	s, _ := c.raw[key].(string)
	return s
}

// Bool returns the value at key as a bool, or false if missing or not a bool.
func (c *Claims) Bool(key string) bool {
	if c == nil {
		return false
	}
	b, _ := c.raw[key].(bool)
	return b
}

// StringSlice returns the value at key as []string. It accepts:
//   - []string (returned as-is)
//   - []any whose elements are strings (filtered)
//   - string (returned as a single-element slice)
//
// Returns nil for any other type or when the claim is missing. The
// permissive []any handling exists because JSON unmarshal into map[string]any
// always produces []any for arrays.
func (c *Claims) StringSlice(key string) []string {
	if c == nil {
		return nil
	}
	switch v := c.raw[key].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		return []string{v}
	}
	return nil
}

// HasStringInSlice reports whether StringSlice(key) contains v. This is the
// most common predicate used by policies (e.g. "is X in the permissions
// list?").
func (c *Claims) HasStringInSlice(key, v string) bool {
	for _, s := range c.StringSlice(key) {
		if s == v {
			return true
		}
	}
	return false
}

// Map returns the value at key as map[string]any. Useful for nested claims
// such as Zitadel's "urn:zitadel:iam:org:project:roles", which is itself a
// map of role-name -> {orgID: orgDomain}.
//
// Returns nil if the claim is missing or not a JSON object.
func (c *Claims) Map(key string) map[string]any {
	if c == nil {
		return nil
	}
	m, _ := c.raw[key].(map[string]any)
	return m
}
