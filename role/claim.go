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
	"github.com/yahoojapan/athenz-authorizer/v4/access"
)

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
	access.BaseClaim
}
