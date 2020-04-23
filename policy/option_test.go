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
	"net/http"
	"reflect"
	"testing"
	"time"

	authcore "github.com/yahoo/athenz/libs/go/zmssvctoken"
	urlutil "github.com/yahoojapan/athenz-authorizer/v3/internal/url"
	"github.com/yahoojapan/athenz-authorizer/v3/pubkey"
)

func TestWithExpireMargin(t *testing.T) {
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
				"1h",
			},
			checkFunc: func(opt Option) error {
				pol := &policyd{}
				if err := opt(pol); err != nil {
					return err
				}
				if pol.expireMargin != time.Hour {
					return fmt.Errorf("Error")
				}

				return nil
			},
		}, {
			name: "invalid format",
			args: args{
				"dummy",
			},
			checkFunc: func(opt Option) error {
				pol := &policyd{}
				if err := opt(pol); err == nil {
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
				pol := &policyd{}
				if err := opt(pol); err != nil {
					return err
				}
				if !reflect.DeepEqual(pol, &policyd{}) {
					return fmt.Errorf("expected no changes, but got %v", pol)
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithExpireMargin(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithExpireMargin() error = %v", err)
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
		want    *policyd
		wantErr error
	}{
		{
			name: "empty string",
			args: args{
				"",
			},
			want:    &policyd{athenzURL: ""},
			wantErr: nil,
		},
		{
			name: "no scheme",
			args: args{
				"dummy.com",
			},
			want:    &policyd{athenzURL: "dummy.com"},
			wantErr: nil,
		},
		{
			name: "http scheme",
			args: args{
				"http://dummy.com",
			},
			want:    &policyd{athenzURL: "dummy.com"},
			wantErr: nil,
		},
		{
			name: "https scheme",
			args: args{
				"https://dummy.com",
			},
			want:    &policyd{athenzURL: "dummy.com"},
			wantErr: nil,
		},
		{
			name: "unsupported scheme",
			args: args{
				"ftp://dummy.com",
			},
			want:    &policyd{athenzURL: ""},
			wantErr: urlutil.ErrUnsupportedScheme,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := &policyd{}
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
				[]string{"domain1", "domain2"},
			},
			checkFunc: func(opt Option) error {
				pol := &policyd{}
				if err := opt(pol); err != nil {
					return err
				}
				if !equalStringSlice(pol.athenzDomains, []string{"domain1", "domain2"}) {
					return fmt.Errorf("Error")
				}

				return nil
			},
		},
		{
			name: "empty value",
			args: args{
				nil,
			},
			checkFunc: func(opt Option) error {
				pol := &policyd{}
				if err := opt(pol); err != nil {
					return err
				}
				if !reflect.DeepEqual(pol, &policyd{}) {
					return fmt.Errorf("expected no changes, but got %v", pol)
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

func TestWithPolicyExpiredDuration(t *testing.T) {
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
				"1h",
			},
			checkFunc: func(opt Option) error {
				pol := &policyd{}
				if err := opt(pol); err != nil {
					return err
				}
				if pol.policyExpiredDuration != time.Hour {
					return fmt.Errorf("Error")
				}

				return nil
			},
		}, {
			name: "invalid format",
			args: args{
				"dummy",
			},
			checkFunc: func(opt Option) error {
				pol := &policyd{}
				if err := opt(pol); err == nil {
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
				pol := &policyd{}
				if err := opt(pol); err != nil {
					return err
				}
				if !reflect.DeepEqual(pol, &policyd{}) {
					return fmt.Errorf("expected no changes, but got %v", pol)
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithPolicyExpiredDuration(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithPolicyExpiredDuration() error = %v", err)
			}
		})
	}
}

func TestWithRefreshDuration(t *testing.T) {
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
				"1h",
			},
			checkFunc: func(opt Option) error {
				pol := &policyd{}
				if err := opt(pol); err != nil {
					return err
				}
				if pol.refreshDuration != time.Hour {
					return fmt.Errorf("Error")
				}

				return nil
			},
		}, {
			name: "invalid format",
			args: args{
				"dummy",
			},
			checkFunc: func(opt Option) error {
				pol := &policyd{}
				if err := opt(pol); err == nil {
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
				pol := &policyd{}
				if err := opt(pol); err != nil {
					return err
				}
				if !reflect.DeepEqual(pol, &policyd{}) {
					return fmt.Errorf("expected no changes, but got %v", pol)
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithRefreshDuration(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithRefreshDuration() error = %v", err)
			}
		})
	}
}

func TestWithHTTPClient(t *testing.T) {
	type args struct {
		c *http.Client
	}
	type test struct {
		name      string
		args      args
		checkFunc func(Option) error
	}
	tests := []test{
		func() test {
			c := &http.Client{}
			return test{
				name: "set success",
				args: args{
					c: c,
				},
				checkFunc: func(opt Option) error {
					pol := &policyd{}
					if err := opt(pol); err != nil {
						return err
					}
					if pol.client != c {
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
				pol := &policyd{}
				if err := opt(pol); err != nil {
					return err
				}
				if !reflect.DeepEqual(pol, &policyd{}) {
					return fmt.Errorf("expected no changes, but got %v", pol)
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithHTTPClient(tt.args.c)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithHTTPClient() error = %v", err)
			}
		})
	}
}

func TestWithPubKeyProvider(t *testing.T) {
	type args struct {
		pkp pubkey.Provider
	}
	type test struct {
		name      string
		args      args
		checkFunc func(Option) error
	}
	tests := []test{
		func() test {
			pkp := pubkey.Provider(func(pubkey.AthenzEnv, string) authcore.Verifier {
				return nil
			})
			return test{
				name: "set success",
				args: args{
					pkp: pkp,
				},
				checkFunc: func(opt Option) error {
					pol := &policyd{}
					if err := opt(pol); err != nil {
						return err
					}
					if reflect.ValueOf(pol.pkp) != reflect.ValueOf(pkp) {
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
				pol := &policyd{}
				if err := opt(pol); err != nil {
					return err
				}
				if !reflect.DeepEqual(pol, &policyd{}) {
					return fmt.Errorf("expected no changes, but got %v", pol)
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithPubKeyProvider(tt.args.pkp)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithPubKeyProvider() error = %v", err)
			}
		})
	}
}

func TestWithErrRetryInterval(t *testing.T) {
	type args struct {
		i string
	}
	tests := []struct {
		name      string
		args      args
		checkFunc func(Option) error
	}{
		{
			name: "set success",
			args: args{
				"1h",
			},
			checkFunc: func(opt Option) error {
				pol := &policyd{}
				if err := opt(pol); err != nil {
					return err
				}
				if pol.errRetryInterval != time.Hour {
					return fmt.Errorf("Error")
				}

				return nil
			},
		}, {
			name: "invalid format",
			args: args{
				"dummy",
			},
			checkFunc: func(opt Option) error {
				pol := &policyd{}
				if err := opt(pol); err == nil {
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
				pol := &policyd{}
				if err := opt(pol); err != nil {
					return err
				}
				if !reflect.DeepEqual(pol, &policyd{}) {
					return fmt.Errorf("expected no changes, but got %v", pol)
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithErrRetryInterval(tt.args.i)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithErrRetryInterval() error= %v", err)
			}
		})
	}
}

func equalStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
