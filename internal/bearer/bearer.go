// Package bearer extracts and validates Bearer tokens from gRPC incoming
// metadata. It is internal to zitadel-grpc-auth so the parsing semantics can
// evolve without becoming part of the public API.
package bearer

import (
	"strings"

	"google.golang.org/grpc/metadata"
)

// FromIncomingMetadata extracts the bearer token (without the "Bearer "
// prefix) from the "authorization" metadata header. Returns the empty string
// if the header is missing, has no value, or is not a Bearer scheme.
//
// The match on "Bearer " is case-insensitive on the scheme as required by
// RFC 6750 §2.1.
func FromIncomingMetadata(md metadata.MD) string {
	if md == nil {
		return ""
	}
	values := md.Get("authorization")
	if len(values) == 0 {
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
	return strings.TrimSpace(v[len(prefix):])
}
