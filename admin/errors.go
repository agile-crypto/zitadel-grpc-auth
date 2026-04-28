package admin

import "errors"

var (
	ErrProjectNotConfigured = errors.New("admin: project not configured")
	ErrUserNotFound         = errors.New("admin: user not found")
	ErrInvalidPattern       = errors.New("admin: invalid glob pattern")
)
