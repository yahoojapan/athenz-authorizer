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
	urlutil "github.com/yahoojapan/athenz-authorizer/v2/internal/url"
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

func TestWithPolicyErrRetryInterval(t *testing.T) {
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
				if authz.policyErrRetryInterval != "dummy" {
					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithPolicyErrRetryInterval(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithPolicyErrRetryInterval() error = %v", err)
			}
		})
	}
}
func TestWithPolicyRefreshDuration(t *testing.T) {
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
				if authz.policyRefreshDuration != "dummy" {
					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithPolicyRefreshDuration(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithPolicyRefreshDuration() error = %v", err)
			}
		})
	}
}
func TestWithPubkeyRefreshDuration(t *testing.T) {
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
				if authz.pubkeyRefreshDuration != "dummy" {
					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithPubkeyRefreshDuration(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithPubkeyRefreshDuration() error = %v", err)
			}
		})
	}
}
func TestWithPubkeyErrRetryInterval(t *testing.T) {
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
				if authz.pubkeyErrRetryInterval != "dummy" {
					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithPubkeyErrRetryInterval(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithPubkeyErrRetryInterval() error = %v", err)
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

func TestWithPubkeyEtagExpTime(t *testing.T) {
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
				if authz.pubkeyEtagExpTime != "dummy" {
					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithPubkeyEtagExpTime(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithPubkeyEtagExpTime() error = %v", err)
			}
		})
	}
}
func TestWithPubkeyEtagFlushDuration(t *testing.T) {
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
				if authz.pubkeyEtagFlushDur != "dummy" {
					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithPubkeyEtagFlushDuration(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithPubkeyEtagFlushDuration() error = %v", err)
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

func TestWithPolicyExpireMargin(t *testing.T) {
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
				if authz.policyExpireMargin != "dummy" {
					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithPolicyExpireMargin(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithPolicyExpireMargin() error = %v", err)
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

func TestWithJwkRefreshDuration(t *testing.T) {
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
				if authz.jwkRefreshDuration != "dummy" {
					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithJwkRefreshDuration(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithJwkRefreshDuration() error = %v", err)
			}
		})
	}
}
func TestWithJwkErrRetryInterval(t *testing.T) {
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
				if authz.jwkErrRetryInterval != "dummy" {

					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithJwkErrRetryInterval(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithJwkErrRetryInterval() error = %v", err)
			}
		})
	}
}

func TestNewATProcessorParam(t *testing.T) {
	type args struct {
		verifyCertThumbprint bool
		certBackdateDur      string
		certOffsetDur        string
	}
	tests := []struct {
		name string
		args args
		want ATProcessorParam
	}{
		{
			name: "create success",
			args: args{
				verifyCertThumbprint: true,
				certBackdateDur:      "2h",
				certOffsetDur:        "2h",
			},
			want: ATProcessorParam{
				verifyCertThumbprint: true,
				certBackdateDur:      "2h",
				certOffsetDur:        "2h",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewATProcessorParam(tt.args.verifyCertThumbprint, tt.args.certBackdateDur, tt.args.certOffsetDur); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewATProcessorParam() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWithATProcessorParam(t *testing.T) {
	type args struct {
		atpParams []ATProcessorParam
	}
	type test struct {
		name      string
		args      args
		checkFunc func(Option) error
	}
	tests := []test{
		func() test {
			atpParams := []ATProcessorParam{
				NewATProcessorParam(true, "2h", "2h"),
			}
			return test{
				name: "set success",
				args: args{
					atpParams: atpParams,
				},
				checkFunc: func(opt Option) error {
					authz := &authorizer{}
					if err := opt(authz); err != nil {
						return err
					}
					if !reflect.DeepEqual(authz.atpParams, atpParams) {
						return fmt.Errorf("invalid param was set")
					}
					return nil
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithATProcessorParam(tt.args.atpParams)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithATProcessorParam() = %v error: %v", got, err)
			}
		})
	}
}

func TestWithRTVerifyRoleToken(t *testing.T) {
	type args struct {
		b bool
	}
	type test struct {
		name      string
		args      args
		checkFunc func(Option) error
	}
	tests := []test{
		func() test {
			isEnable := true
			return test{
				name: "set success",
				args: args{
					b: isEnable,
				},
				checkFunc: func(opt Option) error {
					authz := &authorizer{}
					if err := opt(authz); err != nil {
						return err
					}
					if authz.verifyRoleToken != isEnable {
						return fmt.Errorf("invalid param was set")
					}
					return nil
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithRTVerifyRoleToken(tt.args.b)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithRTVerifyRoleToken() = %v error: %v", got, err)
			}
		})
	}
}

func TestWithRTHeader(t *testing.T) {
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
					if !reflect.DeepEqual(authz.rtHeader, header) {
						return fmt.Errorf("invalid param was set")
					}
					return nil
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithRTHeader(tt.args.h)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithRTHeader() = %v error: %v", got, err)
			}
		})
	}
}

func TestWithRCVerifyRoleCert(t *testing.T) {
	type args struct {
		b bool
	}
	type test struct {
		name      string
		args      args
		checkFunc func(Option) error
	}
	tests := []test{
		func() test {
			isEnable := true
			return test{
				name: "set success",
				args: args{
					b: isEnable,
				},
				checkFunc: func(opt Option) error {
					authz := &authorizer{}
					if err := opt(authz); err != nil {
						return err
					}
					if authz.verifyRoleCert != isEnable {
						return fmt.Errorf("invalid param was set")
					}
					return nil
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithRCVerifyRoleCert(tt.args.b)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithRCVerifyRoleCert() = %v error: %v", got, err)
			}
		})
	}
}
