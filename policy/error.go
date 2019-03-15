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
