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
package access

import (
	"github.com/dgrijalva/jwt-go"
	"reflect"
	"testing"
)

func Test_OAuth2AccessTokenClaim_GetName(t *testing.T) {
	type fields struct {
		Subject   string
		Scope     []string
		Audience  string
		IssuedAt  int64
		ExpiresAt int64
		ClientID  string
	}
	tests := []struct {
		name           string
		fields         fields
		wantName       string
		wantRoles      []string
		wantDomain     string
		wantIssueTime  int64
		wantExpiryTime int64
		wantClientID   string
	}{
		{
			name: "get name success",
			fields: fields{
				Subject:   "principal",
				Scope:     []string{"role1", "role2", "role3"},
				Audience:  "domain",
				IssuedAt:  1595809911,
				ExpiresAt: 1595809926,
				ClientID:  "client_id",
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
			b := BaseClaim{jwt.StandardClaims{
				Audience:  tt.fields.Audience,
				ExpiresAt: tt.fields.ExpiresAt,
				IssuedAt:  tt.fields.IssuedAt,
				Subject:   tt.fields.Subject,
			}}
			at := &OAuth2AccessTokenClaim{
				Scope:     tt.fields.Scope,
				ClientID:  tt.fields.ClientID,
				BaseClaim: b,
			}
			if got := at.GetName(); got != tt.wantName {
				t.Errorf("Token.GetName() = %v, want %v", got, tt.wantName)
			}
		})
	}
}

func Test_OAuth2AccessTokenClaim_GetRoles(t *testing.T) {
	type fields struct {
		Subject   string
		Scope     []string
		Audience  string
		IssuedAt  int64
		ExpiresAt int64
		ClientID  string
	}
	tests := []struct {
		name           string
		fields         fields
		wantName       string
		wantRoles      []string
		wantDomain     string
		wantIssueTime  int64
		wantExpiryTime int64
		wantClientID   string
	}{
		{
			name: "get name success",
			fields: fields{
				Subject:   "principal",
				Scope:     []string{"role1", "role2", "role3"},
				Audience:  "domain",
				IssuedAt:  1595809911,
				ExpiresAt: 1595809926,
				ClientID:  "client_id",
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
			b := BaseClaim{jwt.StandardClaims{
				Audience:  tt.fields.Audience,
				ExpiresAt: tt.fields.ExpiresAt,
				IssuedAt:  tt.fields.IssuedAt,
				Subject:   tt.fields.Subject,
			}}
			at := &OAuth2AccessTokenClaim{
				Scope:     tt.fields.Scope,
				ClientID:  tt.fields.ClientID,
				BaseClaim: b,
			}
			if got := at.GetRoles(); !reflect.DeepEqual(got, tt.wantRoles) {
				t.Errorf("Token.GetRoles() = %v, want %v", got, tt.wantRoles)
			}
		})
	}
}

func Test_OAuth2AccessTokenClaim_GetDomain(t *testing.T) {
	type fields struct {
		Subject   string
		Scope     []string
		Audience  string
		IssuedAt  int64
		ExpiresAt int64
		ClientID  string
	}
	tests := []struct {
		name           string
		fields         fields
		wantName       string
		wantRoles      []string
		wantDomain     string
		wantIssueTime  int64
		wantExpiryTime int64
		wantClientID   string
	}{
		{
			name: "get name success",
			fields: fields{
				Subject:   "principal",
				Scope:     []string{"role1", "role2", "role3"},
				Audience:  "domain",
				IssuedAt:  1595809911,
				ExpiresAt: 1595809926,
				ClientID:  "client_id",
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
			b := BaseClaim{jwt.StandardClaims{
				Audience:  tt.fields.Audience,
				ExpiresAt: tt.fields.ExpiresAt,
				IssuedAt:  tt.fields.IssuedAt,
				Subject:   tt.fields.Subject,
			}}
			at := &OAuth2AccessTokenClaim{
				Scope:     tt.fields.Scope,
				ClientID:  tt.fields.ClientID,
				BaseClaim: b,
			}
			if got := at.GetDomain(); got != tt.wantDomain {
				t.Errorf("Token.GetDomain() = %v, want %v", got, tt.wantDomain)
			}
		})
	}
}

func Test_OAuth2AccessTokenClaim_GetIssueTime(t *testing.T) {
	type fields struct {
		Subject   string
		Scope     []string
		Audience  string
		IssuedAt  int64
		ExpiresAt int64
		ClientID  string
	}
	tests := []struct {
		name           string
		fields         fields
		wantName       string
		wantRoles      []string
		wantDomain     string
		wantIssueTime  int64
		wantExpiryTime int64
		wantClientID   string
	}{
		{
			name: "get name success",
			fields: fields{
				Subject:   "principal",
				Scope:     []string{"role1", "role2", "role3"},
				Audience:  "domain",
				IssuedAt:  1595809911,
				ExpiresAt: 1595809926,
				ClientID:  "client_id",
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
			b := BaseClaim{jwt.StandardClaims{
				Audience:  tt.fields.Audience,
				ExpiresAt: tt.fields.ExpiresAt,
				IssuedAt:  tt.fields.IssuedAt,
				Subject:   tt.fields.Subject,
			}}
			at := &OAuth2AccessTokenClaim{
				Scope:     tt.fields.Scope,
				ClientID:  tt.fields.ClientID,
				BaseClaim: b,
			}
			if got := at.GetIssueTime(); got != tt.wantIssueTime {
				t.Errorf("Token.GetIssueTime() = %v, want %v", got, tt.wantIssueTime)
			}
		})
	}
}

func Test_OAuth2AccessTokenClaim_GetExpiryTime(t *testing.T) {
	type fields struct {
		Subject   string
		Scope     []string
		Audience  string
		IssuedAt  int64
		ExpiresAt int64
		ClientID  string
	}
	tests := []struct {
		name           string
		fields         fields
		wantName       string
		wantRoles      []string
		wantDomain     string
		wantIssueTime  int64
		wantExpiryTime int64
		wantClientID   string
	}{
		{
			name: "get name success",
			fields: fields{
				Subject:   "principal",
				Scope:     []string{"role1", "role2", "role3"},
				Audience:  "domain",
				IssuedAt:  1595809911,
				ExpiresAt: 1595809926,
				ClientID:  "client_id",
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
			b := BaseClaim{jwt.StandardClaims{
				Audience:  tt.fields.Audience,
				ExpiresAt: tt.fields.ExpiresAt,
				IssuedAt:  tt.fields.IssuedAt,
				Subject:   tt.fields.Subject,
			}}
			at := &OAuth2AccessTokenClaim{
				Scope:     tt.fields.Scope,
				ClientID:  tt.fields.ClientID,
				BaseClaim: b,
			}
			if got := at.GetExpiryTime(); got != tt.wantExpiryTime {
				t.Errorf("Token.GetExpiryTime() = %v, want %v", got, tt.wantExpiryTime)
			}
		})
	}
}

func Test_OAuth2AccessTokenClaim_GetClientID(t *testing.T) {
	type fields struct {
		Subject   string
		Scope     []string
		Audience  string
		IssuedAt  int64
		ExpiresAt int64
		ClientID  string
	}
	tests := []struct {
		name           string
		fields         fields
		wantName       string
		wantRoles      []string
		wantDomain     string
		wantIssueTime  int64
		wantExpiryTime int64
		wantClientID   string
	}{
		{
			name: "get name success",
			fields: fields{
				Subject:   "principal",
				Scope:     []string{"role1", "role2", "role3"},
				Audience:  "domain",
				IssuedAt:  1595809911,
				ExpiresAt: 1595809926,
				ClientID:  "client_id",
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
			b := BaseClaim{jwt.StandardClaims{
				Audience:  tt.fields.Audience,
				ExpiresAt: tt.fields.ExpiresAt,
				IssuedAt:  tt.fields.IssuedAt,
				Subject:   tt.fields.Subject,
			}}
			at := &OAuth2AccessTokenClaim{
				Scope:     tt.fields.Scope,
				ClientID:  tt.fields.ClientID,
				BaseClaim: b,
			}
			if got := at.GetClientID(); got != tt.wantClientID {
				t.Errorf("Token.GetClientID() = %v, want %v", got, tt.wantClientID)
			}
		})
	}
}
