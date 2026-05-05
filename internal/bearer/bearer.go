// Package bearer extracts and validates Bearer tokens from gRPC incoming
// metadata. It is internal to zitadel-grpc-auth so the parsing semantics can
// evolve without becoming part of the public API.
package bearer

import (
	"strings"

	"google.golang.org/grpc/metadata"
)

// FromIncomingMetadata extracts the bearer token (without the "Bearer "
// prefix) from the "authorization" metadata header. Returns the empty
// string if the header is missing, has no value, is not a Bearer scheme,
// is duplicated (more than one authorization value), or contains
// disallowed control characters.
//
// The match on "Bearer " is case-insensitive on the scheme as required by
// RFC 6750 §2.1. The token itself must be a sequence of printable ASCII
// per RFC 6750 §2.1 (b64token = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~"
// / "+" / "/" ) *"="); we relax that to "no control characters and no
// whitespace inside" so we accept any opaque token Zitadel might mint
// while still rejecting smuggling attempts (CR/LF, NUL, embedded spaces).
//
// Rejecting duplicate authorization values protects against header
// smuggling attacks (an attacker injects a second header to override a
// proxy-attached one) and makes operator misconfiguration loud rather
// than silent.
func FromIncomingMetadata(md metadata.MD) string {
	if md == nil {
		return ""
	}
	values := md.Get("authorization")
	if len(values) == 0 {
		return ""
	}
	if len(values) > 1 {
		// Loud rejection: duplicate authorization headers are a smuggling
		// signal, not a legitimate transport pattern.
		return ""
	}
	v := values[0]
	const prefix = "bearer "
	if len(v) < len(prefix) {
		return ""
	}
	if !strings.EqualFold(v[:len(prefix)], prefix) {
		return ""
	}
	tok := strings.TrimSpace(v[len(prefix):])
	if tok == "" {
		return ""
	}
	for _, r := range tok {
		if r < 0x21 || r == 0x7f {
			// control char, space, or DEL — reject
			return ""
		}
	}
	return tok
}
