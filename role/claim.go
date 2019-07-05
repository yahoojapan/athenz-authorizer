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

// Claim represents role jwt claim data.
type Claim struct {
	Domain   string `json:"d"`
	Email    string `json:"email"`
	KeyID    string `json:"k"`
	MFA      string `json:"mfa"`
	Role     string `json:"r"`
	Salt     string `json:"a"`
	UserID   string `json:"u"`
	UserName string `json:"n"`
	Version  string `json:"v"`
	jwt.StandardClaims
}

// copy from source code, and change c.VerifyExpiresAt parameter.
func (c *Claim) Valid() error {
	vErr := new(jwt.ValidationError)
	now := jwt.TimeFunc().Unix()

	if c.VerifyExpiresAt(now, true) == false {
		delta := time.Unix(now, 0).Sub(time.Unix(c.ExpiresAt, 0))
		vErr.Inner = fmt.Errorf("token is expired by %v", delta)
		vErr.Errors |= jwt.ValidationErrorExpired
	}

	if c.VerifyIssuedAt(now, false) == false {
		vErr.Inner = fmt.Errorf("Token used before issued")
		vErr.Errors |= jwt.ValidationErrorIssuedAt
	}

	if c.VerifyNotBefore(now, false) == false {
		vErr.Inner = fmt.Errorf("token is not valid yet")
		vErr.Errors |= jwt.ValidationErrorNotValidYet
	}

	if vErr.Errors == 0 {
		return nil
	}

	return vErr
}
