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

package access

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
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

// OAuth2AccessTokenClaim represents access token claim data.
// based on https://github.com/AthenZ/athenz/blob/0e7335dbfa9d41eef0b049c07e7f846bff0f3169/libs/java/auth_core/src/main/java/com/AthenZ/athenz/auth/token/AccessToken.java#L382
type OAuth2AccessTokenClaim struct {
	AuthTime       int64             `json:"auth_time"`
	Version        int               `json:"ver"`
	ClientID       string            `json:"client_id"`
	UserID         string            `json:"uid"`
	ProxyPrincipal string            `json:"proxy,omitempty"`
	Scope          []string          `json:"scp"`
	Confirm        map[string]string `json:"cnf"`
	BaseClaim
}
