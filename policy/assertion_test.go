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
	"fmt"
	"reflect"
	"regexp"
	"testing"

	"github.com/pkg/errors"
)

func TestNewAssertion(t *testing.T) {
	type args struct {
		action   string
		resource string
		effect   string
	}
	tests := []struct {
		name      string
		args      args
		want      *Assertion
		checkFunc func(got, want *Assertion) error
		wantErr   error
	}{
		{
			name: "return effect success",
			args: args{
				resource: "dom:res",
				action:   "act",
				effect:   "allow",
			},
			want: &Assertion{
				Action:         "act",
				Resource:       "res",
				ResourceDomain: "dom",
				ActionRegexp: func() *regexp.Regexp {
					r, _ := regexp.Compile("^act$")
					return r
				}(),
				ResourceRegexp: func() *regexp.Regexp {
					r, _ := regexp.Compile("^res$")
					return r
				}(),
				Effect:               nil,
				ActionRegexpString:   "^act$",
				ResourceRegexpString: "^res$",
			},
			checkFunc: func(got, want *Assertion) error {
				if !reflect.DeepEqual(got, want) {
					return fmt.Errorf("got: %v, want: %v", got, want)
				}

				return nil
			},
		},
		{
			name: "return effect fail",
			args: args{
				resource: "dom:res",
				action:   "act",
				effect:   "deny",
			},
			want: &Assertion{
				Action:         "act",
				Resource:       "res",
				ResourceDomain: "dom",
				ActionRegexp: func() *regexp.Regexp {
					r, _ := regexp.Compile("^act$")
					return r
				}(),
				ResourceRegexp: func() *regexp.Regexp {
					r, _ := regexp.Compile("^res$")
					return r
				}(),
				Effect:               errors.New("policy deny: Access Check was explicitly denied"),
				ActionRegexpString:   "^act$",
				ResourceRegexpString: "^res$",
			},
			checkFunc: func(got, want *Assertion) error {
				if got.ResourceDomain != want.ResourceDomain ||
					!reflect.DeepEqual(got.ActionRegexp, want.ActionRegexp) ||
					!reflect.DeepEqual(got.ResourceRegexp, want.ResourceRegexp) ||
					got.Effect.Error() != want.Effect.Error() {
					return fmt.Errorf("got: %v, want: %v", got, want)
				}

				return nil
			},
		},
		{
			name: "create assertion with wildcard",
			args: args{
				resource: "dom:*[res]?",
				action:   "*[act]?",
				effect:   "allow",
			},
			want: &Assertion{
				Action:         "*[act]?",
				Resource:       "*[res]?",
				ResourceDomain: "dom",
				ActionRegexp: func() *regexp.Regexp {
					r, _ := regexp.Compile("^.*\\[act].$")
					return r
				}(),
				ResourceRegexp: func() *regexp.Regexp {
					r, _ := regexp.Compile("^.*\\[res].$")
					return r
				}(),
				Effect:               nil,
				ActionRegexpString:   "^.*\\[act].$",
				ResourceRegexpString: "^.*\\[res].$",
			},
			checkFunc: func(got, want *Assertion) error {
				if !reflect.DeepEqual(got, want) {
					return fmt.Errorf("got: %v, want: %v", got, want)
				}

				return nil
			},
		},
		{
			name: "resource domain not valid",
			args: args{
				resource: "domres",
				action:   "act",
				effect:   "deny",
			},
			wantErr: errors.New("assertion format not correct: Access denied due to invalid/empty policy resources"),
		},
		{
			name: "invalid regex, but not return error",
			args: args{
				resource: "dom:res(",
				action:   "act",
				effect:   "deny",
			},
			want: &Assertion{
				Action:         "act",
				Resource:       "dom:res(",
				ResourceDomain: "dom",
				ActionRegexp: func() *regexp.Regexp {
					r, _ := regexp.Compile("^act$")
					return r
				}(),
				ResourceRegexp: func() *regexp.Regexp {
					r, _ := regexp.Compile("^res\\($")
					return r
				}(),
				Effect:               errors.New("policy deny: Access Check was explicitly denied"),
				ActionRegexpString:   "^act$",
				ResourceRegexpString: "^res\\($",
			},
			checkFunc: func(got, want *Assertion) error {
				if got.ResourceDomain != want.ResourceDomain ||
					!reflect.DeepEqual(got.ActionRegexp, want.ActionRegexp) ||
					!reflect.DeepEqual(got.ResourceRegexp, want.ResourceRegexp) ||
					got.Effect.Error() != want.Effect.Error() {
					return fmt.Errorf("got: %v, want: %v", got, want)
				}

				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewAssertion(tt.args.action, tt.args.resource, tt.args.effect)
			if tt.checkFunc != nil {
				if err := tt.checkFunc(got, tt.want); err != nil {
					t.Errorf("NewAssertion error: %v", err)
				}
			}
			if err == nil {
				if tt.wantErr != nil {
					t.Errorf("NewAssertion = %v, wantErr %v", err, tt.wantErr)
				}
			} else {
				if tt.wantErr == nil {
					t.Errorf("NewAssertion error = %v, wantErr %v", err, tt.wantErr)
				} else if err.Error() != tt.wantErr.Error() {
					t.Errorf("NewAssertion error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}

func Test_isRegexMetaCharacter(t *testing.T) {
	type args struct {
		target rune
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "check '^', return true",
			args: args{
				target: '^',
			},
			want: true,
		},
		{
			name: "check '$', return true",
			args: args{
				target: '$',
			},
			want: true,
		},
		{
			name: "check '.', return true",
			args: args{
				target: '.',
			},
			want: true,
		},
		{
			name: "check ')', return true",
			args: args{
				target: ')',
			},
			want: true,
		},
		{
			name: "check '*', return false",
			args: args{
				target: '*',
			},
			want: false,
		},
		{
			name: "check ']', return false",
			args: args{
				target: ']',
			},
			want: false,
		},
		{
			name: "check 'a', return false",
			args: args{
				target: 'a',
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRegexMetaCharacter(tt.args.target); got != tt.want {
				t.Errorf("isRegexMetaCharacter() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_patternFromGlob(t *testing.T) {
	type args struct {
		glob string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "check to escape regular expression meta characters",
			args: args{
				glob: "^$.|[+\\(){",
			},
			want: "^\\^\\$\\.\\|\\[\\+\\\\\\(\\)\\{$",
		},
		{
			name: "check to convert wildcards",
			args: args{
				glob: ".*wild?card?-*test*",
			},
			want: "^\\..*wild.card.-.*test.*$",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := patternFromGlob(tt.args.glob)
			if got != tt.want {
				t.Errorf("patternFromGlob() = %v, want %v", got, tt.want)
			}
			if _, err := regexp.Compile(got); err != nil {
				t.Errorf("regexp.Compile() error = %v, got %v", err, got)
			}
		})
	}
}
