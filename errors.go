package providerd

import (
	"errors"

	"github.com/yahoojapan/athenz-policy-updater/policy"
	"github.com/yahoojapan/athenz-policy-updater/role"
)

type Effect int

const (
	// ErrDomainEmpty "Access denied due to no policies in the domain file"
	ErrDomainEmpty Effect = iota + 1

	// ErrCertMismatchIssuer "Access denied due to certificate mismatch in issuer"
	ErrCertMismatchIssuer
	// ErrCertMissingSubject "Access denied due to missing subject in certificate"
	ErrCertMissingSubject
	// ErrCertMissingDomain "Access denied due to missing domain name in certificate"
	ErrCertMissingDomain
	// ErrCertMissingRoleName "Access denied due to missing role name in certificate"
	ErrCertMissingRoleName
	// ErrContextCanceled
	ErrContextCanceled
)

var (
	ErrRoleTokenInvalid = role.ErrRoleTokenInvalid
	ErrRoleTokenExpired = role.ErrRoleTokenExpired

	ErrDomainMismatch = policy.ErrDomainMismatch
	ErrDomainNotFound = policy.ErrDomainNotFound
	ErrDomainExpired  = policy.ErrDomainExpired

	ErrNoMatch               = policy.ErrNoMatch
	ErrInvalidPolicyResource = policy.ErrInvalidPolicyResource
	ErrDenyByPolicy          = policy.ErrDenyByPolicy
	ErrFetchPolicy           = policy.ErrFetchPolicy

	ErrInvalidParameters = errors.New("Access denied due to invalid/empty action/resource values")
)

/*
func (e Effect) String() string {
	switch e {
	case ErrDenyByPolicy:
		return "Access Check was explicitly denied"
	case ErrNoMatch:
		return "Access denied due to no match to any of the assertions defined in domain policy file"
	case ErrRoleTokenExpired:
		return "Access denied due to expired RoleToken"
	case ErrRoleTokenInvalid:
		return "Access denied due to invalid RoleToken"
	case ErrDomainMismatch:
		return "Access denied due to domain mismatch between Resource and RoleToken"
	case ErrDomainNotFound:
		return "Access denied due to domain not found in library cache"
	case ErrDomainExpired:
		return "Access denied due to expired domain policy file"
	case ErrDomainEmpty:
		return "Access denied due to no policies in the domain file"
	case ErrInvalidParameters:
		return "Access denied due to invalid/empty action/resource values"
	case ErrCertMismatchIssuer:
		return "Access denied due to certificate mismatch in issuer"
	case ErrCertMissingSubject:
		return "Access denied due to missing subject in certificate"
	case ErrCertMissingDomain:
		return "Access denied due to missing domain name in certificate"
	case ErrCertMissingRoleName:
		return "Access denied due to missing role name in certificate"
	case ErrInvalidPolicyResource:
		return "Access denied due to invalid/empty policy resources"
	case ErrInvalidToken:
		return "Access denied due to invali/empty role token"
	case ErrContextCanceled:
		return "goroutine context already canceled"
	}
	return ""
}
*/

/*
func (e Effect) Error() string {
	return fmt.Sprintf("error: %s", e.String())
}
*/
