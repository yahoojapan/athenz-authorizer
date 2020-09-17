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
	"reflect"
	"testing"

	"github.com/yahoojapan/athenz-authorizer/v4/jwk"
)

func TestWithJWKProvider(t *testing.T) {
	type args struct {
		jwkp jwk.Provider
	}
	type test struct {
		name      string
		args      args
		checkFunc func(Option) error
	}
	tests := []test{
		func() test {
			pkp := jwk.Provider(func(string, string) interface{} {
				return nil
			})
			return test{
				name: "set success",
				args: args{
					jwkp: pkp,
				},
				checkFunc: func(opt Option) error {
					pol := &atp{}
					if err := opt(pol); err != nil {
						return err
					}
					if reflect.ValueOf(pol.jwkp) != reflect.ValueOf(pkp) {
						return fmt.Errorf("Error")
					}

					return nil
				},
			}
		}(),
		{
			name: "empty value",
			args: args{
				nil,
			},
			checkFunc: func(opt Option) error {
				pol := &atp{}
				if err := opt(pol); err != nil {
					return err
				}
				if !reflect.DeepEqual(pol, &atp{}) {
					return fmt.Errorf("expected no changes, but got %v", pol)
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithJWKProvider(tt.args.jwkp)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithJWKProvider() error:  %v", err)
			}
		})
	}
}

func TestWithEnableMTLSCertificateBoundAccessToken(t *testing.T) {
	type args struct {
		b bool
	}
	tests := []struct {
		name      string
		args      args
		checkFunc func(Option) error
	}{
		{
			name: "set success",
			args: args{
				b: true,
			},
			checkFunc: func(opt Option) error {
				r := &atp{}
				if err := opt(r); err != nil {
					return err
				}
				if !r.enableMTLSCertificateBoundAccessToken {
					return fmt.Errorf("Error")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithEnableMTLSCertificateBoundAccessToken(tt.args.b)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithEnableMTLSCertificateBoundAccessToken() error: %v", err)
			}
		})
	}
}

func TestWithEnableVerifyClientID(t *testing.T) {
	type args struct {
		b bool
	}
	tests := []struct {
		name      string
		args      args
		checkFunc func(Option) error
	}{
		{
			name: "set success",
			args: args{
				b: true,
			},
			checkFunc: func(opt Option) error {
				r := &atp{}
				if err := opt(r); err != nil {
					return err
				}
				if !r.enableVerifyClientID {
					return fmt.Errorf("Error")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithEnableVerifyClientID(tt.args.b)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithEnableVerifyClientID() error: %v", err)
			}
		})
	}
}

func TestWithAuthorizedClientIDs(t *testing.T) {
	type args struct {
		m map[string][]string
	}
	type test struct {
		name      string
		args      args
		checkFunc func(Option) error
	}
	tests := []test{
		func() test {
			normalAuthorizedClientIDs := map[string][]string{
				"cn1": {"cid1a", "cid2b"},
			}
			return test{
				name: "set success",
				args: args{
					m: normalAuthorizedClientIDs,
				},
				checkFunc: func(opt Option) error {
					r := &atp{}
					if err := opt(r); err != nil {
						return err
					}
					if !reflect.DeepEqual(r.authorizedClientIDs, normalAuthorizedClientIDs) {
						return fmt.Errorf("Error")
					}
					return nil
				},
			}
		}(),
		func() test {
			emptyAuthorizedClientIDs := map[string][]string{}
			return test{
				name: "empty value",
				args: args{
					m: emptyAuthorizedClientIDs,
				},
				checkFunc: func(opt Option) error {
					r := &atp{}
					if err := opt(r); err != nil {
						return err
					}
					if !reflect.DeepEqual(r.authorizedClientIDs, emptyAuthorizedClientIDs) {
						return fmt.Errorf("Error")
					}
					return nil
				},
			}
		}(),
		{
			name: "empty value",
			args: args{
				m: nil,
			},
			checkFunc: func(opt Option) error {
				r := &atp{}
				if err := opt(r); err != nil {
					return err
				}
				if r.authorizedClientIDs != nil {
					return fmt.Errorf("Error")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithAuthorizedClientIDs(tt.args.m)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithAuthorizedClientIDs() error: %v", err)
			}
		})
	}
}

func TestWithClientCertificateGoBackSeconds(t *testing.T) {
	type args struct {
		t string
	}
	tests := []struct {
		name      string
		args      args
		checkFunc func(Option) error
	}{
		{
			name: "set success",
			args: args{
				t: "2h",
			},
			checkFunc: func(opt Option) error {
				r := &atp{}
				if err := opt(r); err != nil {
					return err
				}
				if r.clientCertificateGoBackSeconds != 7200 {
					return fmt.Errorf("Error")
				}
				return nil
			},
		},
		{
			name: "empty value",
			args: args{
				t: "",
			},
			checkFunc: func(opt Option) error {
				r := &atp{}
				if err := opt(r); err != nil {
					return err
				}
				if !reflect.DeepEqual(r, &atp{}) {
					return fmt.Errorf("expected no changes, but got %v", r)
				}
				return nil
			},
		},
		{
			name: "invalid format",
			args: args{
				t: "invalid",
			},
			checkFunc: func(opt Option) error {
				r := &atp{}
				if err := opt(r); err == nil {
					return fmt.Errorf("expected error, but not return")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithClientCertificateGoBackSeconds(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithClientCertificateGoBackSeconds() error: %v", err)
			}
		})
	}
}

func TestWithClientCertificateOffsetSeconds(t *testing.T) {
	type args struct {
		t string
	}
	tests := []struct {
		name      string
		args      args
		checkFunc func(Option) error
	}{
		{
			name: "set success",
			args: args{
				t: "2h",
			},
			checkFunc: func(opt Option) error {
				r := &atp{}
				if err := opt(r); err != nil {
					return err
				}
				if r.clientCertificateOffsetSeconds != 7200 {
					return fmt.Errorf("Error")
				}
				return nil
			},
		},
		{
			name: "empty value",
			args: args{
				t: "",
			},
			checkFunc: func(opt Option) error {
				r := &atp{}
				if err := opt(r); err != nil {
					return err
				}
				if !reflect.DeepEqual(r, &atp{}) {
					return fmt.Errorf("expected no changes, but got %v", r)
				}
				return nil
			},
		},
		{
			name: "invalid format",
			args: args{
				t: "invalid",
			},
			checkFunc: func(opt Option) error {
				r := &atp{}
				if err := opt(r); err == nil {
					return fmt.Errorf("expected error, but not return")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithClientCertificateOffsetSeconds(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithClientCertificateOffsetSeconds() error: %v", err)
			}
		})
	}
}
