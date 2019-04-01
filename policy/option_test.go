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
	"github.com/yahoojapan/athenz-policy-updater/config"
)

func TestEtagFlushDur(t *testing.T) {
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
				if pol.etagFlushDur != time.Hour {
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
			got := EtagFlushDur(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("EtagFlushDur() error = %v", err)
			}
		})
	}
}

func TestExpireMargin(t *testing.T) {
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
			got := ExpireMargin(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("ExpireMargin() error = %v", err)
			}
		})
	}
}

func TestEtagExpTime(t *testing.T) {
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
				if pol.etagExpTime != time.Hour {
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
			got := EtagExpTime(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("EtagExpTime() error = %v", err)
			}
		})
	}
}

func TestAthenzURL(t *testing.T) {
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
				"http://dummy.com",
			},
			checkFunc: func(opt Option) error {
				pol := &policyd{}
				if err := opt(pol); err != nil {
					return err
				}
				if pol.athenzURL != "http://dummy.com" {
					return fmt.Errorf("Error")
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
			got := AthenzURL(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("AthenzURL() error = %v", err)
			}
		})
	}
}

func TestAthenzDomains(t *testing.T) {
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
			got := AthenzDomains(tt.args.t...)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("AthenzDomains() error = %v", err)
			}
		})
	}
}

func TestRefreshDuration(t *testing.T) {
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
			got := RefreshDuration(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("RefreshDuration() error = %v", err)
			}
		})
	}
}

func TestHTTPClient(t *testing.T) {
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
			got := HTTPClient(tt.args.c)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("HTTPClient() error = %v", err)
			}
		})
	}
}

func TestPubKeyProvider(t *testing.T) {
	type args struct {
		pkp config.PubKeyProvider
	}
	type test struct {
		name      string
		args      args
		checkFunc func(Option) error
	}
	tests := []test{
		func() test {
			pkp := config.PubKeyProvider(func(config.AthenzEnv, string) authcore.Verifier {
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
			got := PubKeyProvider(tt.args.pkp)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("PubKeyProvider() error = %v", err)
			}
		})
	}
}

func TestErrRetryInterval(t *testing.T) {
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
			got := ErrRetryInterval(tt.args.i)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("ErrRetryInterval() error= %v", err)
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
