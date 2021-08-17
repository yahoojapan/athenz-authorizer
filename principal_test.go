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

import (
	"reflect"
	"testing"
)

func TestPrincipal_Name(t *testing.T) {
	tests := []struct {
		name           string
		p              principal
		wantName       string
		wantRoles      []string
		wantDomain     string
		wantIssueTime  int64
		wantExpiryTime int64
	}{
		{
			name: "success name",
			p: principal{
				name:       "principal",
				roles:      []string{"role1", "role2", "role3"},
				domain:     "domain",
				issueTime:  1595809911,
				expiryTime: 1595809926,
			},
			wantName:       "principal",
			wantRoles:      []string{"role1", "role2", "role3"},
			wantDomain:     "domain",
			wantIssueTime:  1595809911,
			wantExpiryTime: 1595809926,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.Name(); got != tt.wantName {
				t.Errorf("Principal.Name() = %v, want %v", got, tt.wantName)
			}
		})
	}
}

func TestPrincipal_Roles(t *testing.T) {
	tests := []struct {
		name           string
		p              principal
		wantName       string
		wantRoles      []string
		wantDomain     string
		wantIssueTime  int64
		wantExpiryTime int64
	}{
		{
			name: "success roles",
			p: principal{
				name:       "principal",
				roles:      []string{"role1", "role2", "role3"},
				domain:     "domain",
				issueTime:  1595809911,
				expiryTime: 1595809926,
			},
			wantName:       "principal",
			wantRoles:      []string{"role1", "role2", "role3"},
			wantDomain:     "domain",
			wantIssueTime:  1595809911,
			wantExpiryTime: 1595809926,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.Roles(); !reflect.DeepEqual(got, tt.wantRoles) {
				t.Errorf("Principal.Roles() = %v, want %v", got, tt.wantRoles)
			}
		})
	}
}

func TestPrincipal_AuthorizedRoles(t *testing.T) {
	tests := []struct {
		name                string
		p                   principal
		wantName            string
		wantAuthorizedRoles []string
		wantDomain          string
		wantIssueTime       int64
		wantExpiryTime      int64
	}{
		{
			name: "success roles",
			p: principal{
				name:            "principal",
				roles:           []string{"role1", "role2", "role3"},
				authorizedRoles: []string{"role1", "role2"},
				domain:          "domain",
				issueTime:       1595809911,
				expiryTime:      1595809926,
			},
			wantName:            "principal",
			wantAuthorizedRoles: []string{"role1", "role2"},
			wantDomain:          "domain",
			wantIssueTime:       1595809911,
			wantExpiryTime:      1595809926,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.AuthorizedRoles(); !reflect.DeepEqual(got, tt.wantAuthorizedRoles) {
				t.Errorf("Principal.AuthorizedRoles() = %v, want %v", got, tt.wantAuthorizedRoles)
			}
		})
	}
}

func TestPrincipal_Domain(t *testing.T) {
	tests := []struct {
		name           string
		p              principal
		wantName       string
		wantRoles      []string
		wantDomain     string
		wantIssueTime  int64
		wantExpiryTime int64
	}{
		{
			name: "success domain",
			p: principal{
				name:       "principal",
				roles:      []string{"role1", "role2", "role3"},
				domain:     "domain",
				issueTime:  1595809911,
				expiryTime: 1595809926,
			},
			wantName:       "principal",
			wantRoles:      []string{"role1", "role2", "role3"},
			wantDomain:     "domain",
			wantIssueTime:  1595809911,
			wantExpiryTime: 1595809926,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.Domain(); got != tt.wantDomain {
				t.Errorf("Principal.Domain() = %v, want %v", got, tt.wantDomain)
			}
		})
	}
}

func TestPrincipal_IssueTime(t *testing.T) {
	tests := []struct {
		name           string
		p              principal
		wantName       string
		wantRoles      []string
		wantDomain     string
		wantIssueTime  int64
		wantExpiryTime int64
	}{
		{
			name: "success issuetime",
			p: principal{
				name:       "principal",
				roles:      []string{"role1", "role2", "role3"},
				domain:     "domain",
				issueTime:  1595809911,
				expiryTime: 1595809926,
			},
			wantName:       "principal",
			wantRoles:      []string{"role1", "role2", "role3"},
			wantDomain:     "domain",
			wantIssueTime:  1595809911,
			wantExpiryTime: 1595809926,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.IssueTime(); got != tt.wantIssueTime {
				t.Errorf("Principal.IssueTime() = %v, want %v", got, tt.wantIssueTime)
			}
		})
	}
}

func TestPrincipal_ExpiryTime(t *testing.T) {
	tests := []struct {
		name           string
		p              principal
		wantName       string
		wantRoles      []string
		wantDomain     string
		wantIssueTime  int64
		wantExpiryTime int64
	}{
		{
			name: "success expirytime",
			p: principal{
				name:       "principal",
				roles:      []string{"role1", "role2", "role3"},
				domain:     "domain",
				issueTime:  1595809911,
				expiryTime: 1595809926,
			},
			wantName:       "principal",
			wantRoles:      []string{"role1", "role2", "role3"},
			wantDomain:     "domain",
			wantIssueTime:  1595809911,
			wantExpiryTime: 1595809926,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.ExpiryTime(); got != tt.wantExpiryTime {
				t.Errorf("Principal.ExpiryTime() = %v, want %v", got, tt.wantExpiryTime)
			}
		})
	}
}

func TestOAuthAccessToken_ClientID(t *testing.T) {
	tests := []struct {
		name           string
		o              oAuthAccessToken
		wantName       string
		wantRoles      []string
		wantDomain     string
		wantIssueTime  int64
		wantExpiryTime int64
		wantClientID   string
	}{
		{
			name: "success clientid",
			o: oAuthAccessToken{
				principal: principal{
					name:       "principal",
					roles:      []string{"role1", "role2", "role3"},
					domain:     "domain",
					issueTime:  1595809911,
					expiryTime: 1595809926,
				},
				clientID: "client_id",
			},
			wantName:       "principal",
			wantRoles:      []string{"role1", "role2", "role3"},
			wantDomain:     "domain",
			wantIssueTime:  1595809911,
			wantExpiryTime: 1595809926,
			wantClientID:   "client_id",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.o.ClientID(); got != tt.wantClientID {
				t.Errorf("OAuthAccessToken.ClientID() = %v, want %v", got, tt.wantClientID)
			}
		})
	}
}
