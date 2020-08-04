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
package pubkey

import (
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"

	urlutil "github.com/yahoojapan/athenz-authorizer/v4/internal/url"
)

func TestWithAthenzURL(t *testing.T) {
	type args struct {
		url string
	}
	tests := []struct {
		name    string
		args    args
		want    *pubkeyd
		wantErr error
	}{
		{
			name: "empty string",
			args: args{
				"",
			},
			want:    &pubkeyd{athenzURL: ""},
			wantErr: nil,
		},
		{
			name: "no scheme",
			args: args{
				"dummy.com",
			},
			want:    &pubkeyd{athenzURL: "dummy.com"},
			wantErr: nil,
		},
		{
			name: "http scheme",
			args: args{
				"http://dummy.com",
			},
			want:    &pubkeyd{athenzURL: "dummy.com"},
			wantErr: nil,
		},
		{
			name: "https scheme",
			args: args{
				"https://dummy.com",
			},
			want:    &pubkeyd{athenzURL: "dummy.com"},
			wantErr: nil,
		},
		{
			name: "unsupported scheme",
			args: args{
				"ftp://dummy.com",
			},
			want:    &pubkeyd{athenzURL: ""},
			wantErr: urlutil.ErrUnsupportedScheme,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := &pubkeyd{}
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

func TestWithSysAuthDomain(t *testing.T) {
	type args struct {
		domain string
	}
	tests := []struct {
		name      string
		args      args
		checkFunc func(Option) error
	}{
		{
			name: "set sys.auth domain success",
			args: args{
				domain: "dummy",
			},
			checkFunc: func(got Option) error {
				p := &pubkeyd{}
				if err := got(p); err != nil {
					return err
				}

				if p.sysAuthDomain != "dummy" {
					return fmt.Errorf("cannot set sys.auth domain")
				}
				return nil
			},
		},
		{
			name: "set empty string",
			args: args{
				domain: "",
			},
			checkFunc: func(got Option) error {
				p := &pubkeyd{}
				if err := got(p); err != nil {
					return err
				}
				if p.sysAuthDomain != "" {
					return fmt.Errorf("invalid domain wasset")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithSysAuthDomain(tt.args.domain)
			if got == nil {
				t.Errorf("WithSysAuthDomain() = nil")
				return
			}
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithSysAuthDomain() = %v", err)
			}
		})
	}
}

func TestWithETagExpiry(t *testing.T) {
	type args struct {
		time string
	}
	tests := []struct {
		name      string
		args      args
		checkFunc func(Option) error
	}{
		{
			name: "set ETag expiry time success",
			args: args{
				time: "2h",
			},
			checkFunc: func(got Option) error {
				p := &pubkeyd{}
				if err := got(p); err != nil {
					return err
				}

				if p.eTagExpiry != time.Duration(time.Hour*2) {
					return fmt.Errorf("cannot set ETag expiry time")
				}
				return nil
			},
		},
		{
			name: "test set empty string",
			args: args{
				time: "",
			},
			checkFunc: func(got Option) error {
				p := &pubkeyd{}
				if err := got(p); err != nil {
					return err
				}
				if !reflect.DeepEqual(p, &pubkeyd{}) {
					return fmt.Errorf("expected no changes, but got %v", p)
				}
				return nil
			},
		},
		{
			name: "cannot parse string to time.Duration",
			args: args{
				time: "dummy",
			},
			checkFunc: func(got Option) error {
				p := &pubkeyd{}
				err := got(p)

				if err == nil {
					return fmt.Errorf("invalid ETag expiry time was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithETagExpiry(tt.args.time)
			if got == nil {
				t.Errorf("WithETagExpiry() = nil")
				return
			}
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithETagExpiry() = %v", err)
			}
		})
	}
}

func TestWithRetryDelay(t *testing.T) {
	type args struct {
		time string
	}
	tests := []struct {
		name      string
		args      args
		checkFunc func(Option) error
	}{
		{
			name: "set retryDelay expire time success",
			args: args{
				time: "2h",
			},
			checkFunc: func(got Option) error {
				p := &pubkeyd{}
				if err := got(p); err != nil {
					return err
				}

				if p.retryDelay != time.Duration(time.Hour*2) {
					return fmt.Errorf("cannot set retryDelay time")
				}
				return nil
			},
		},
		{
			name: "test set empty string",
			args: args{
				time: "",
			},
			checkFunc: func(got Option) error {
				p := &pubkeyd{}
				if err := got(p); err != nil {
					return err
				}
				if !reflect.DeepEqual(p, &pubkeyd{}) {
					return fmt.Errorf("expected no changes, but got %v", p)
				}
				return nil
			},
		},
		{
			name: "cannot parse string to time.Duration",
			args: args{
				time: "dummy",
			},
			checkFunc: func(got Option) error {
				p := &pubkeyd{}
				err := got(p)

				if err == nil {
					return fmt.Errorf("invalid retryDelay time was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithRetryDelay(tt.args.time)
			if got == nil {
				t.Errorf("WithRetryDelay() = nil")
				return
			}
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithRetryDelay() = %v", err)
			}
		})
	}
}

func TestWithETagPurgePeriod(t *testing.T) {
	type args struct {
		dur string
	}
	tests := []struct {
		name      string
		args      args
		checkFunc func(Option) error
	}{
		{
			name: "set ETag expiry time success",
			args: args{
				dur: "2h",
			},
			checkFunc: func(got Option) error {
				p := &pubkeyd{}
				if err := got(p); err != nil {
					return err
				}

				if p.eTagPurgePeriod != time.Duration(time.Hour*2) {
					return fmt.Errorf("cannot set ETag purge period")
				}
				return nil
			},
		},
		{
			name: "cannot parse string to time.Duration",
			args: args{
				dur: "dummy",
			},
			checkFunc: func(got Option) error {
				p := &pubkeyd{}
				err := got(p)

				if err == nil {
					return fmt.Errorf("invalid ETag purge period was set")
				}
				return nil
			},
		},
		{
			name: "test set empty string",
			args: args{
				dur: "",
			},
			checkFunc: func(got Option) error {
				p := &pubkeyd{}
				if err := got(p); err != nil {
					return err
				}
				if !reflect.DeepEqual(p, &pubkeyd{}) {
					return fmt.Errorf("expected no changes, but got %v", p)
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithETagPurgePeriod(tt.args.dur)
			if got == nil {
				t.Errorf("WithETagPurgePeriod() = nil")
				return
			}
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithETagPurgePeriod() = %v", err)
			}
		})
	}
}

func TestWithRefreshPeriod(t *testing.T) {
	type args struct {
		dur string
	}
	tests := []struct {
		name      string
		args      args
		checkFunc func(Option) error
	}{
		{
			name: "set refresh period success",
			args: args{
				dur: "2h",
			},
			checkFunc: func(got Option) error {
				p := &pubkeyd{}
				if err := got(p); err != nil {
					return err
				}

				if p.refreshPeriod != time.Duration(time.Hour*2) {
					return fmt.Errorf("cannot set refresh period")
				}
				return nil
			},
		},
		{
			name: "cannot parse string to time.Duration",
			args: args{
				dur: "dummy",
			},
			checkFunc: func(got Option) error {
				p := &pubkeyd{}
				err := got(p)

				if err == nil {
					return fmt.Errorf("invalid refresh period was set")
				}
				return nil
			},
		},
		{
			name: "test set empty string",
			args: args{
				dur: "",
			},
			checkFunc: func(got Option) error {
				p := &pubkeyd{}
				if err := got(p); err != nil {
					return err
				}
				if !reflect.DeepEqual(p, &pubkeyd{}) {
					return fmt.Errorf("expected no changes, but got %v", p)
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithRefreshPeriod(tt.args.dur)
			if got == nil {
				t.Errorf("WithRefreshPeriod() = nil")
				return
			}
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithRefreshPeriod() = %v", err)
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
					cd := &pubkeyd{}
					if err := opt(cd); err != nil {
						return err
					}
					if cd.client != c {
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
				cd := &pubkeyd{}
				if err := opt(cd); err != nil {
					return err
				}
				if !reflect.DeepEqual(cd, &pubkeyd{}) {
					return fmt.Errorf("expected no changes, but got %v", cd)
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
