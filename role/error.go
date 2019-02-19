package role

import "github.com/pkg/errors"

var (
	// ErrInvalidToken ""
	ErrRoleTokenInvalid = errors.New("Access denied due to invalid RoleToken")

	ErrRoleTokenExpired = errors.New("Access denied due to expired RoleToken")
)
