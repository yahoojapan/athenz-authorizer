/*
Copyright (C)  2020 Yahoo Japan Corporation Athenz team.

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

// A Principal is an authenticated entity
type Principal interface {
	Name() string
	Roles() []string
	Domain() string
	IssueTime() int64
	ExpiryTime() int64
}

// A OAuthAccessToken is an interface for a principal that has a OAuthAccessToken
type OAuthAccessToken interface {
	ClientID() string
}

type principal struct {
	name       string
	roles      []string
	domain     string
	issueTime  int64
	expiryTime int64
}

type oAuthAccessToken struct {
	principal
	clientID string
}

// Return the principal's name
func (p *principal) Name() string {
	return p.name
}

// Return the principal's roles
func (p *principal) Roles() []string {
	return p.roles
}

// Return the principal's domain
func (p *principal) Domain() string {
	return p.domain
}

// Return the principal's issuetime
func (p *principal) IssueTime() int64 {
	return p.issueTime
}

// Return the principal's expiryTime
func (p *principal) ExpiryTime() int64 {
	return p.expiryTime
}

// Return the principal's clientid
func (c *oAuthAccessToken) ClientID() string {
	return c.clientID
}