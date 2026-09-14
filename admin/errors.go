package admin

import "errors"

var (
	ErrProjectNotConfigured    = errors.New("admin: project not configured")
	ErrUserNotFound            = errors.New("admin: user not found")
	ErrUserTypeMismatch        = errors.New("admin: user type mismatch")
	ErrApplicationTypeMismatch = errors.New("admin: application type mismatch")
	ErrAmbiguousResource       = errors.New("admin: ambiguous resource")
	ErrInvalidPattern          = errors.New("admin: invalid glob pattern")
)
