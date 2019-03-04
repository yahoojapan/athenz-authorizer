package policy

import "github.com/pkg/errors"

var (
	// ErrDomainMismatch ""
	ErrDomainMismatch = errors.New("Access denied due to domain mismatch between Resource and RoleToken")
	// ErrDomainNotFound "e"
	ErrDomainNotFound = errors.New("Access denied due to domain not found in library cache")
	// ErrNoMatch ""
	ErrNoMatch = errors.New("Access denied due to no match to any of the assertions defined in domain policy file")
	// ErrInvalidResource ""
	ErrInvalidPolicyResource = errors.New("Access denied due to invalie/empty policy resources")
	// ErrDenyByPolicy "Access Check was explicitly denied"
	ErrDenyByPolicy = errors.New("Access Check was explicitly denied")
	// ErrDomainExpired "Access denied due to expired domain policy file"
	ErrDomainExpired = errors.New("Access denied due to expired domain policy file")

	ErrFetchPolicy = errors.New("Error fetching athenz policy")
)
