package auth

import (
	"errors"
	"fmt"
)

// ErrUnauthenticated is the sentinel returned (or wrapped) by policies and
// interceptors when a request lacks a valid identity. Server interceptors
// translate this into gRPC codes.Unauthenticated.
var ErrUnauthenticated = errors.New("unauthenticated")

// ErrForbidden is the sentinel returned (or wrapped) by policies and
// interceptors when an authenticated identity lacks authorization for the
// requested operation. Server interceptors translate this into gRPC
// codes.PermissionDenied.
var ErrForbidden = errors.New("forbidden")

// Unauthenticated returns an error wrapping [ErrUnauthenticated] with a
// formatted message. Use this from a [PolicyFunc] (or anywhere in a handler)
// to signal that the caller's identity could not be established.
func Unauthenticated(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrUnauthenticated}, args...)...)
}

// Forbidden returns an error wrapping [ErrForbidden] with a formatted message.
// Use this from a [PolicyFunc] (or anywhere in a handler) to signal that the
// caller is authenticated but not authorized for the requested operation.
func Forbidden(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrForbidden}, args...)...)
}

// IsUnauthenticated reports whether err is or wraps [ErrUnauthenticated].
func IsUnauthenticated(err error) bool { return errors.Is(err, ErrUnauthenticated) }

// IsForbidden reports whether err is or wraps [ErrForbidden].
func IsForbidden(err error) bool { return errors.Is(err, ErrForbidden) }
