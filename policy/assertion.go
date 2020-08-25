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
	"regexp"
	"strings"

	"github.com/pkg/errors"
)

// Assertion represents the refined assertion data use in policy checking
type Assertion struct {
	ResourceDomain string         `json:"resource_domain"`
	ActionRegexp   *regexp.Regexp `json:"-"`
	ResourceRegexp *regexp.Regexp `json:"-"`
	Effect         error          `json:"effect"`

	Action               string `json:"action"`
	Resource             string `json:"resource"`
	ActionRegexpString   string `json:"action_regexp_string"`
	ResourceRegexpString string `json:"resource_regexp_string"`
}

// NewAssertion returns the Assertion object or error
func NewAssertion(action, resource, effect string) (*Assertion, error) {
	domres := strings.SplitN(resource, ":", 2)
	if len(domres) < 2 {
		return nil, errors.Wrap(ErrInvalidPolicyResource, "assertion format not correct")
	}
	dom := domres[0]
	res := domres[1]

	ar, err := regexp.Compile(patternFromGlob(strings.ToLower(action)))
	if err != nil {
		return nil, errors.Wrap(err, "assertion format not correct")
	}

	rr, err := regexp.Compile(patternFromGlob(strings.ToLower(res)))
	if err != nil {
		return nil, errors.Wrap(err, "assertion format not correct")
	}

	return &Assertion{
		ResourceDomain: dom,
		ActionRegexp:   ar,
		ResourceRegexp: rr,
		Effect: func() error {
			if strings.EqualFold("deny", effect) {
				return errors.Wrap(ErrDenyByPolicy, "policy deny")
			}
			return nil
		}(),
		Action:               action,
		Resource:             res,
		ActionRegexpString:   ar.String(),
		ResourceRegexpString: rr.String(),
	}, nil
}

func isRegexMetaCharacter(target rune) bool {
	switch target {
	case '^':
	case '$':
	case '.':
	case '|':
	case '[':
	case '+':
	case '\\':
	case '(':
	case ')':
	case '{':
	default:
		return false
	}
	return true
}

func patternFromGlob(glob string) string {
	var sb strings.Builder
	sb.WriteString("^")
	for _, c := range glob {
		if c == '*' {
			sb.WriteString(".*")
		} else if c == '?' {
			sb.WriteString(".")
		} else {
			if isRegexMetaCharacter(c) {
				sb.WriteString("\\")
			}
			sb.WriteRune(c)
		}
	}
	sb.WriteString("$")
	return sb.String()
}
