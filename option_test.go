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
package authorizerd

import (
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/kpango/gache"
	urlutil "github.com/yahoojapan/athenz-authorizer/v3/internal/url"
)

func TestWithEnablePubkeyd(t *testing.T) {
	tests := []struct {
		name      string
		checkFunc func(Option) error
	}{
		{
			name: "set success",
			checkFunc: func(opt Option) error {
				authz := &authorizer{}
				if err := opt(authz); err != nil {
					return err
				}
				if authz.disablePubkeyd != false {
					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithEnablePubkeyd()
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithEnablePubkeyd() error = %v", err)
			}
		})
	}
}

func TestWithDisablePubkeyd(t *testing.T) {
	tests := []struct {
		name      string
		checkFunc func(Option) error
	}{
		{
			name: "set success",
			checkFunc: func(opt Option) error {
				authz := &authorizer{}
				if err := opt(authz); err != nil {
					return err
				}
				if authz.disablePubkeyd != true {
					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithDisablePubkeyd()
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithDisablePubkeyd() error = %v", err)
			}
		})
	}
}

func TestWithPolicyRetryDelay(t *testing.T) {
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
				t: "dummy",
			},
			checkFunc: func(opt Option) error {
				authz := &authorizer{}
				if err := opt(authz); err != nil {
					return err
				}
				if authz.policyRetryDelay != "dummy" {
					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithPolicyRetryDelay(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithPolicyRetryDelay() error = %v", err)
			}
		})
	}
}

func TestWithPolicyRetryAttempts(t *testing.T) {
	type args struct {
		c int
	}
	tests := []struct {
		name      string
		args      args
		checkFunc func(Option) error
	}{
		{
			name: "set success",
			args: args{
				c: 2,
			},
			checkFunc: func(opt Option) error {
				authz := &authorizer{}
				if err := opt(authz); err != nil {
					return err
				}
				if authz.policyRetryAttempts != 2 {
					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithPolicyRetryAttempts(tt.args.c)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithPolicyRetryAttempts() error = %v", err)
			}
		})
	}
}

func TestWithPolicyRefreshPeriod(t *testing.T) {
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
				t: "dummy",
			},
			checkFunc: func(opt Option) error {
				authz := &authorizer{}
				if err := opt(authz); err != nil {
					return err
				}
				if authz.policyRefreshPeriod != "dummy" {
					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithPolicyRefreshPeriod(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithPolicyRefreshPeriod() error = %v", err)
			}
		})
	}
}
func TestWithPubkeyRefreshPeriod(t *testing.T) {
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
				t: "dummy",
			},
			checkFunc: func(opt Option) error {
				authz := &authorizer{}
				if err := opt(authz); err != nil {
					return err
				}
				if authz.pubkeyRefreshPeriod != "dummy" {
					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithPubkeyRefreshPeriod(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithPubkeyRefreshPeriod() error = %v", err)
			}
		})
	}
}
func TestWithPubkeyRetryDelay(t *testing.T) {
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
				t: "dummy",
			},
			checkFunc: func(opt Option) error {
				authz := &authorizer{}
				if err := opt(authz); err != nil {
					return err
				}
				if authz.pubkeyRetryDelay != "dummy" {
					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithPubkeyRetryDelay(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithPubkeyRetryDelay() error = %v", err)
			}
		})
	}
}

func TestWithAthenzURL(t *testing.T) {
	type args struct {
		url string
	}
	tests := []struct {
		name    string
		args    args
		want    *authorizer
		wantErr error
	}{
		{
			name: "empty string",
			args: args{
				"",
			},
			want:    &authorizer{athenzURL: ""},
			wantErr: nil,
		},
		{
			name: "no scheme",
			args: args{
				"dummy.com",
			},
			want:    &authorizer{athenzURL: "dummy.com"},
			wantErr: nil,
		},
		{
			name: "http scheme",
			args: args{
				"http://dummy.com",
			},
			want:    &authorizer{athenzURL: "dummy.com"},
			wantErr: nil,
		},
		{
			name: "https scheme",
			args: args{
				"https://dummy.com",
			},
			want:    &authorizer{athenzURL: "dummy.com"},
			wantErr: nil,
		},
		{
			name: "unsupported scheme",
			args: args{
				"ftp://dummy.com",
			},
			want:    &authorizer{athenzURL: ""},
			wantErr: urlutil.ErrUnsupportedScheme,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := &authorizer{}
			err := WithAthenzURL(tt.args.url)(got)
			if err != tt.wantErr {
				t.Errorf("WithAthenzURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("WithAthenzURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWithAthenzTimeout(t *testing.T) {
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
				"30s",
			},
			checkFunc: func(opt Option) error {
				authz := &authorizer{}
				if err := opt(authz); err != nil {
					return err
				}
				if authz.athenzTimeout != 30*time.Second {
					return fmt.Errorf("Error")
				}

				return nil
			},
		},
		{
			name: "invalid format",
			args: args{
				"dummy",
			},
			checkFunc: func(opt Option) error {
				authz := &authorizer{}
				if err := opt(authz); err == nil {
					return fmt.Errorf("expected error, but not return")
				}

				return nil
			},
		},
		{
			name: "empty value",
			args: args{
				"",
			},
			checkFunc: func(opt Option) error {
				authz := &authorizer{}
				if err := opt(authz); err != nil {
					return err
				}
				if !reflect.DeepEqual(authz, &authorizer{}) {
					return fmt.Errorf("expected no changes, but got %v", authz)
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithAthenzTimeout(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithAthenzTimeout() error = %v", err)
			}
		})
	}
}

func TestWithAthenzCAPath(t *testing.T) {
	type args struct {
		p string
	}
	tests := []struct {
		name      string
		args      args
		checkFunc func(Option) error
	}{
		{
			name: "set success",
			args: args{
				p: "dummy",
			},
			checkFunc: func(opt Option) error {
				authz := &authorizer{}
				if err := opt(authz); err != nil {
					return err
				}
				if authz.athenzCAPath != "dummy" {
					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithAthenzCAPath(tt.args.p)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithAthenzCAPath() error = %v", err)
			}
		})
	}
}

func TestWithAthenzDomains(t *testing.T) {
	type args struct {
		t []string
	}
	tests := []struct {
		name      string
		args      args
		checkFunc func(Option) error
	}{
		{
			name: "set success",
			args: args{
				t: []string{"dummy1", "dummy2"},
			},
			checkFunc: func(opt Option) error {
				authz := &authorizer{}
				if err := opt(authz); err != nil {
					return err
				}
				if !reflect.DeepEqual(authz.athenzDomains, []string{"dummy1", "dummy2"}) {
					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithAthenzDomains(tt.args.t...)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithAthenzDomains() error = %v", err)
			}
		})
	}
}

func TestWithPubkeySysAuthDomain(t *testing.T) {
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
				t: "dummy",
			},
			checkFunc: func(opt Option) error {
				authz := &authorizer{}
				if err := opt(authz); err != nil {
					return err
				}
				if authz.pubkeySysAuthDomain != "dummy" {
					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithPubkeySysAuthDomain(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithPubkeySysAuthDomain() error = %v", err)
			}
		})
	}
}

func TestWithPubkeyETagExpiry(t *testing.T) {
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
				t: "dummy",
			},
			checkFunc: func(opt Option) error {
				authz := &authorizer{}
				if err := opt(authz); err != nil {
					return err
				}
				if authz.pubkeyETagExpiry != "dummy" {
					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithPubkeyETagExpiry(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithPubkeyETagExpiry() error = %v", err)
			}
		})
	}
}

func TestWithPubkeyETagPurgePeriod(t *testing.T) {
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
				t: "dummy",
			},
			checkFunc: func(opt Option) error {
				authz := &authorizer{}
				if err := opt(authz); err != nil {
					return err
				}
				if authz.pubkeyETagPurgePeriod != "dummy" {
					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithPubkeyETagPurgePeriod(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithPubkeyETagPurgePeriod() error = %v", err)
			}
		})
	}
}

func TestWithEnablePolicyd(t *testing.T) {
	tests := []struct {
		name      string
		checkFunc func(Option) error
	}{
		{
			name: "set success",
			checkFunc: func(opt Option) error {
				authz := &authorizer{}
				if err := opt(authz); err != nil {
					return err
				}
				if authz.disablePolicyd != false {
					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithEnablePolicyd()
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithEnablePolicyd() error = %v", err)
			}
		})
	}
}

func TestWithDisablePolicyd(t *testing.T) {
	tests := []struct {
		name      string
		checkFunc func(Option) error
	}{
		{
			name: "set success",
			checkFunc: func(opt Option) error {
				authz := &authorizer{}
				if err := opt(authz); err != nil {
					return err
				}
				if authz.disablePolicyd != true {
					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithDisablePolicyd()
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithDisablePolicyd() error = %v", err)
			}
		})
	}
}

func TestWithPolicyExpiryMargin(t *testing.T) {
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
				t: "dummy",
			},
			checkFunc: func(opt Option) error {
				authz := &authorizer{}
				if err := opt(authz); err != nil {
					return err
				}
				if authz.policyExpiryMargin != "dummy" {
					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithPolicyExpiryMargin(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithPolicyExpiryMargin() error = %v", err)
			}
		})
	}
}

func TestWithCacheExp(t *testing.T) {
	type args struct {
		d time.Duration
	}
	tests := []struct {
		name      string
		args      args
		checkFunc func(Option) error
	}{
		{
			name: "set success",
			args: args{
				d: time.Duration(time.Hour * 2),
			},
			checkFunc: func(opt Option) error {
				authz := &authorizer{
					cache: gache.New(),
				}
				if err := opt(authz); err != nil {
					return err
				}
				if authz.cacheExp != time.Duration(time.Hour*2) {
					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithCacheExp(tt.args.d)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithCacheExp() error = %v", err)
			}
		})
	}
}

func TestWithRoleCertURIPrefix(t *testing.T) {
	type args struct {
		p string
	}
	tests := []struct {
		name      string
		args      args
		checkFunc func(Option) error
	}{
		{
			name: "set success",
			args: args{
				p: "dummy",
			},
			checkFunc: func(opt Option) error {
				authz := &authorizer{}
				if err := opt(authz); err != nil {
					return err
				}
				if authz.roleCertURIPrefix != "dummy" {
					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithRoleCertURIPrefix(tt.args.p)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithRoleCertURIPrefix() error = %v", err)
			}
		})
	}
}

func TestWithTransport(t *testing.T) {
	type args struct {
		t *http.Transport
	}
	tests := []struct {
		name      string
		args      args
		checkFunc func(Option) error
	}{
		{
			name: "set success",
			args: args{
				t: &http.Transport{},
			},
			checkFunc: func(opt Option) error {
				authz := &authorizer{}
				if err := opt(authz); err != nil {
					return err
				}
				if !reflect.DeepEqual(authz.client.Transport, &http.Transport{}) {
					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
		{
			name: "set nil",
			args: args{
				t: nil,
			},
			checkFunc: func(opt Option) error {
				authz := &authorizer{}
				if err := opt(authz); err != nil {
					return err
				}
				want := &http.Client{
					Timeout: time.Second * 30,
				}
				if !reflect.DeepEqual(authz.client, want) {
					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithTransport(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithTransport() error = %v", err)
			}
		})
	}
}

func TestWithEnableJwkd(t *testing.T) {
	tests := []struct {
		name      string
		checkFunc func(Option) error
	}{
		{
			name: "set success",
			checkFunc: func(opt Option) error {
				authz := &authorizer{}
				if err := opt(authz); err != nil {
					return err
				}
				if authz.disableJwkd != false {
					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithEnableJwkd()
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithEnableJwkd() error = %v", err)
			}
		})
	}
}

func TestWithDisableJwkd(t *testing.T) {
	tests := []struct {
		name      string
		checkFunc func(Option) error
	}{
		{
			name: "set success",
			checkFunc: func(opt Option) error {
				authz := &authorizer{}
				if err := opt(authz); err != nil {
					return err
				}
				if authz.disableJwkd != true {
					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithDisableJwkd()
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithDisableJwkd() error = %v", err)
			}
		})
	}
}

func TestWithJwkRefreshPeriod(t *testing.T) {
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
				t: "dummy",
			},
			checkFunc: func(opt Option) error {
				authz := &authorizer{}
				if err := opt(authz); err != nil {
					return err
				}
				if authz.jwkRefreshPeriod != "dummy" {
					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithJwkRefreshPeriod(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithJwkRefreshPeriod() error = %v", err)
			}
		})
	}
}
func TestWithJwkRetryDelay(t *testing.T) {
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
				t: "dummy",
			},
			checkFunc: func(opt Option) error {
				authz := &authorizer{}
				if err := opt(authz); err != nil {
					return err
				}
				if authz.jwkRetryDelay != "dummy" {

					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithJwkRetryDelay(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithJwkRetryDelay() error = %v", err)
			}
		})
	}
}

func TestNewAccessTokenParam(t *testing.T) {
	type args struct {
		enable               bool
		verifyCertThumbprint bool
		verifyClientID       bool
		authorizedClientIDs  map[string][]string
		certBackdateDur      string
		certOffsetDur        string
	}
	tests := []struct {
		name string
		args args
		want AccessTokenParam
	}{
		{
			name: "create success",
			args: args{
				verifyCertThumbprint: true,
				certBackdateDur:      "2h",
				certOffsetDur:        "2h",
			},
			want: AccessTokenParam{
				verifyCertThumbprint: true,
				certBackdateDur:      "2h",
				certOffsetDur:        "2h",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewAccessTokenParam(
				tt.args.enable,
				tt.args.verifyCertThumbprint,
				tt.args.certBackdateDur,
				tt.args.certOffsetDur,
				tt.args.verifyClientID,
				tt.args.authorizedClientIDs,
			); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewAccessTokenParam() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWithAccessTokenParams(t *testing.T) {
	type args struct {
		accessTokenParam AccessTokenParam
	}
	type test struct {
		name      string
		args      args
		checkFunc func(Option) error
	}
	tests := []test{
		func() test {
			accessTokenParam :=
				NewAccessTokenParam(true, true, "1h", "1h", true, map[string][]string{
					"common_name1": []string{"client_id1", "client_id2"},
					"common_name2": []string{"client_id1", "client_id2"},
				})

			return test{
				name: "set success",
				args: args{
					accessTokenParam: accessTokenParam,
				},
				checkFunc: func(opt Option) error {
					authz := &authorizer{}
					if err := opt(authz); err != nil {
						return err
					}
					if !reflect.DeepEqual(authz.accessTokenParam, accessTokenParam) {
						return fmt.Errorf("invalid param was set")
					}
					return nil
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithAccessTokenParam(tt.args.accessTokenParam)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithAccessTokenParam() = %v error: %v", got, err)
			}
		})
	}
}

func TestWithEnableRoleToken(t *testing.T) {
	type test struct {
		name      string
		checkFunc func(Option) error
	}
	tests := []test{
		func() test {
			return test{
				name: "set success",
				checkFunc: func(opt Option) error {
					authz := &authorizer{}
					if err := opt(authz); err != nil {
						return err
					}
					if authz.enableRoleToken != true {
						return fmt.Errorf("invalid param was set")
					}
					return nil
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithEnableRoleToken()
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithEnableRoleToken() = %v error: %v", got, err)
			}
		})
	}
}

func TestWithDisableRoleToken(t *testing.T) {
	type test struct {
		name      string
		checkFunc func(Option) error
	}
	tests := []test{
		func() test {
			return test{
				name: "set success",
				checkFunc: func(opt Option) error {
					authz := &authorizer{}
					if err := opt(authz); err != nil {
						return err
					}
					if authz.enableRoleToken != false {
						return fmt.Errorf("invalid param was set")
					}
					return nil
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithDisableRoleToken()
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithDisableRoleToken() = %v error: %v", got, err)
			}
		})
	}
}

func TestWithRoleAuthHeader(t *testing.T) {
	type args struct {
		h string
	}
	type test struct {
		name      string
		args      args
		checkFunc func(Option) error
	}
	tests := []test{
		func() test {
			header := "TEST-HEADER"
			return test{
				name: "set success",
				args: args{
					h: header,
				},
				checkFunc: func(opt Option) error {
					authz := &authorizer{}
					if err := opt(authz); err != nil {
						return err
					}
					if !reflect.DeepEqual(authz.roleAuthHeader, header) {
						return fmt.Errorf("invalid param was set")
					}
					return nil
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithRoleAuthHeader(tt.args.h)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithRoleAuthHeader() = %v error: %v", got, err)
			}
		})
	}
}

func TestWithEnableRoleCert(t *testing.T) {
	type test struct {
		name      string
		checkFunc func(Option) error
	}
	tests := []test{
		func() test {
			return test{
				name: "set success",
				checkFunc: func(opt Option) error {
					authz := &authorizer{}
					if err := opt(authz); err != nil {
						return err
					}
					if authz.enableRoleCert != true {
						return fmt.Errorf("invalid param was set")
					}
					return nil
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithEnableRoleCert()
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithEnableRoleCert() = %v error: %v", got, err)
			}
		})
	}
}

func TestWithDisableRoleCert(t *testing.T) {
	type test struct {
		name      string
		checkFunc func(Option) error
	}
	tests := []test{
		func() test {
			return test{
				name: "set success",
				checkFunc: func(opt Option) error {
					authz := &authorizer{}
					if err := opt(authz); err != nil {
						return err
					}
					if authz.enableRoleCert != false {
						return fmt.Errorf("invalid param was set")
					}
					return nil
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithDisableRoleCert()
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithDisableRoleCert() = %v error: %v", got, err)
			}
		})
	}
}
