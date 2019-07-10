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

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/pkg/errors"
)

var (
	replacer = strings.NewReplacer(".*", ".*", "*", ".*")
)

// Assertion represents the refined assertion data use in policy checking
type Assertion struct {
	Action   string
	Resource string

	ResourceDomain string
	Reg            *regexp.Regexp
	Effect         error
}

// NewAssertion returns the Assertion object or error
func NewAssertion(action, resource, effect string) (*Assertion, error) {
	domres := strings.SplitN(resource, ":", 2)
	if len(domres) < 2 {
		return nil, errors.Wrap(ErrInvalidPolicyResource, "assertion format not correct")
	}
	dom := domres[0]
	res := domres[1]

	regexStr := "^" + replacer.Replace(strings.ToLower(action+"-"+res)) + "$"
	reg, err := regexp.Compile(regexStr)
	if err != nil {
		return nil, errors.Wrap(err, "assertion format not correct")
	}

	return &Assertion{
		Action:         action,
		Resource:       res,
		ResourceDomain: dom,
		Reg:            reg,
		Effect: func() error {
			if strings.EqualFold("deny", effect) {
				return errors.Wrap(ErrDenyByPolicy, "policy deny")
			}
			return nil
		}(),
	}, nil
}

// AssertionJSON represents json format of Assertion
type AssertionJSON struct {
	Action         string `json:"action"`
	Resource       string `json:"resource"`
	ResourceDomain string `json:"domain"`
	Reg            string `json:"reg"`
	Deny           bool   `json:"deny"`
}

// MarshalJSON implements the Marshaler interface.
func (a *Assertion) MarshalJSON() ([]byte, error) {
	x := &AssertionJSON{
		Action:         a.Action,
		Resource:       a.Resource,
		ResourceDomain: a.ResourceDomain,
		Reg:            a.Reg.String(),
		Deny:           a.Effect == nil,
	}
	return json.Marshal(x)
}
