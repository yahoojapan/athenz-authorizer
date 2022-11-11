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
// based on https://github.com/AthenZ/athenz/blob/e85e233555247f2a4239bf302825e1bbf9493af9/libs/java/auth_core/src/main/java/com/yahoo/athenz/auth/token/AccessToken.java#L468-L476
type OAuth2AccessTokenClaim struct {
	AuthTime       int64                  `json:"auth_time"`
	Version        int                    `json:"ver"`
	ClientID       string                 `json:"client_id"`
	UserID         string                 `json:"uid"`
	ProxyPrincipal string                 `json:"proxy,omitempty"`
	Scope          []string               `json:"scp"`
	Confirm        map[string]interface{} `json:"cnf"`
	BaseClaim
}
