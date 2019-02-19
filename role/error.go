package role

import "github.com/pkg/errors"

var (
	// ErrRoleTokenInvalid "Access denied due to invalid RoleToken"
	ErrRoleTokenInvalid = errors.New("Access denied due to invalid RoleToken")

	// ErrRoleTokenExpired "Access denied due to expired RoleToken"
	ErrRoleTokenExpired = errors.New("Access denied due to expired RoleToken")
)
