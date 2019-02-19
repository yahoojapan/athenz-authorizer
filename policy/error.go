package policy

import "github.com/pkg/errors"

var (
	// ErrDomainMismatch "Access denied due to domain mismatch between Resource and RoleToken"
	ErrDomainMismatch = errors.New("Access denied due to domain mismatch between Resource and RoleToken")

	// ErrDomainNotFound "Access denied due to domain not found in library cache"
	ErrDomainNotFound = errors.New("Access denied due to domain not found in library cache")

	// ErrNoMatch "Access denied due to no match to any of the assertions defined in domain policy file"
	ErrNoMatch = errors.New("Access denied due to no match to any of the assertions defined in domain policy file")

	// ErrInvalidPolicyResource "Access denied due to invalie/empty policy resources"
	ErrInvalidPolicyResource = errors.New("Access denied due to invalie/empty policy resources")

	// ErrDenyByPolicy "Access Check was explicitly denied"
	ErrDenyByPolicy = errors.New("Access Check was explicitly denied")

	// ErrDomainExpired "Access denied due to expired domain policy file"
	ErrDomainExpired = errors.New("Access denied due to expired domain policy file")

	// ErrFetchPolicy "Error fetching athenz policy"
	ErrFetchPolicy = errors.New("Error fetching athenz policy")
)
