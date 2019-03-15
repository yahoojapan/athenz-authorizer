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
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// RoleToken represents role token data.
type RoleToken struct {
	// Version    string   // required
	Domain string   // required
	Roles  []string // required
	// Principal  string   // required
	// Host       string
	// Salt       string    // required
	// TimeStamp  time.Time // required
	ExpiryTime time.Time // required
	KeyID      string    // required
	// IP         string
	// ProxyUser  string
	Signature string // required

	UnsignedToken string
}

// SetParams sets the value for corresponding key data.
func (r *RoleToken) SetParams(key, value string) error {
	switch key {
	// case "a":
	// r.Salt = value
	case "d":
		r.Domain = value
	case "e":
		i, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return errors.Wrap(err, "invalid expiry time")
		}
		r.ExpiryTime = time.Unix(i, 0)
	// case "h":
	// r.Host = value
	// case "i":
	// r.IP = value
	case "k":
		r.KeyID = value
	// case "p":
	// r.Principal = value
	case "r":
		r.Roles = strings.Split(value, ",")
	case "s":
		r.Signature = value
		// case "t":
		// i, err := strconv.ParseInt(value, 10, 64)
		// if err != nil {
		// return err
		// }
		// r.TimeStamp = time.Unix(i, 0)
		// case "proxy":
		// r.ProxyUser = value
		// case "v":
		// r.Version = value
	}

	return nil
}

// Expired returns if the role token is expired or not.
func (r *RoleToken) Expired() bool {
	return time.Now().After(r.ExpiryTime)
}
