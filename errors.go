/*
Copyright (C)  2018 Yahoo Japan Corporation Athenz team.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package authorizerd

import (
	"errors"

	"github.com/yahoojapan/athenz-authorizer/v2/policy"
	"github.com/yahoojapan/athenz-authorizer/v2/role"
)

var (
	// ErrRoleTokenInvalid "Access denied due to invalid RoleToken"
	ErrRoleTokenInvalid = role.ErrRoleTokenInvalid
	// ErrRoleTokenExpired "Access denied due to expired RoleToken"
	ErrRoleTokenExpired = role.ErrRoleTokenExpired

	// ErrDomainMismatch "Access denied due to domain mismatch between Resource and RoleToken"
	ErrDomainMismatch = policy.ErrDomainMismatch
	// ErrDomainNotFound "Access denied due to domain not found in library cache"
	ErrDomainNotFound = policy.ErrDomainNotFound
	// ErrDomainExpired "Access denied due to expired domain policy file"
	ErrDomainExpired = policy.ErrDomainExpired
	// ErrNoMatch "Access denied due to no match to any of the assertions defined in domain policy file"
	ErrNoMatch = policy.ErrNoMatch
	// ErrInvalidPolicyResource "Access denied due to invalid/empty policy resources"
	ErrInvalidPolicyResource = policy.ErrInvalidPolicyResource
	// ErrDenyByPolicy "Access Check was explicitly denied"
	ErrDenyByPolicy = policy.ErrDenyByPolicy
	// ErrFetchPolicy "Error fetching athenz policy"
	ErrFetchPolicy = policy.ErrFetchPolicy

	// ErrInvalidParameters "Access denied due to invalid/empty action/resource values"
	ErrInvalidParameters = errors.New("Access denied due to invalid/empty action/resource values")

	// ErrInvalidCredentials "Access denied due to invalid credentials"
	ErrInvalidCredentials = errors.New("Access denied due to invalid credentials")
)

/*
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
*/

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
