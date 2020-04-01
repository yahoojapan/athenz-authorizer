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

package role

import (
	"fmt"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

type BaseClaim struct {
	jwt.StandardClaims
}

// Valid is copy from source code, and changed c.VerifyExpiresAt parameter.
func (c *BaseClaim) Valid() error {
	vErr := new(jwt.ValidationError)
	now := jwt.TimeFunc().Unix()

	if !c.VerifyExpiresAt(now, true) {
		delta := time.Unix(now, 0).Sub(time.Unix(c.ExpiresAt, 0))
		vErr.Inner = fmt.Errorf("token is expired by %v", delta)
		vErr.Errors |= jwt.ValidationErrorExpired
	}

	if !c.VerifyIssuedAt(now, false) {
		vErr.Inner = fmt.Errorf("Token used before issued")
		vErr.Errors |= jwt.ValidationErrorIssuedAt
	}

	if !c.VerifyNotBefore(now, false) {
		vErr.Inner = fmt.Errorf("token is not valid yet")
		vErr.Errors |= jwt.ValidationErrorNotValidYet
	}

	if vErr.Errors == 0 {
		return nil
	}

	return vErr
}

// RoleJWTClaim represents role jwt claim data.
type RoleJWTClaim struct {
	Domain   string `json:"d"`
	Email    string `json:"email"`
	KeyID    string `json:"k"`
	MFA      string `json:"mfa"`
	Role     string `json:"r"`
	Salt     string `json:"a"`
	UserID   string `json:"u"`
	UserName string `json:"n"`
	Version  string `json:"v"`
	BaseClaim
}

// ZTSAccessTokenClaim represents access token claim data.
// based on https://github.com/yahoo/athenz/blob/0e7335dbfa9d41eef0b049c07e7f846bff0f3169/libs/java/auth_core/src/main/java/com/yahoo/athenz/auth/token/AccessToken.java#L382
type ZTSAccessTokenClaim struct {
	AuthTime       int64             `json:"auth_time"`
	Version        int               `json:"ver"`
	ClientID       string            `json:"client_id"`
	UserID         string            `json:"uid"`
	ProxyPrincipal string            `json:"proxy,omitempty"`
	Scope          []string          `json:"scp"`
	Confirm        map[string]string `json:"cnf"`
	BaseClaim
}
