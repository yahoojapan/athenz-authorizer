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
package config

import (
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"
)

func TestAthenzURL(t *testing.T) {
	type args struct {
		athenzURL string
	}
	tests := []struct {
		name      string
		args      args
		checkFunc func(Option) error
	}{
		{
			name: "set empty string",
			args: args{
				athenzURL: "",
			},
			checkFunc: func(got Option) error {
				c := &confd{}
				got(c)

				if c.athenzURL != "" {
					return fmt.Errorf("invalid url was set")
				}
				return nil
			},
		},
		{
			name: "set athenz url success",
			args: args{
				athenzURL: "dummy",
			},
			checkFunc: func(got Option) error {
				c := &confd{}
				got(c)

				if c.athenzURL != "dummy" {
					return fmt.Errorf("cannot set athenz url")
				}
				return nil
			},
		},
		{
			name: "remove http:// prefix",
			args: args{
				athenzURL: "http://dummy",
			},
			checkFunc: func(got Option) error {
				c := &confd{}
				got(c)

				if c.athenzURL != "dummy" {
					return fmt.Errorf("cannot set athenz url")
				}
				return nil
			},
		},
		{
			name: "remove https:// prefix",
			args: args{
				athenzURL: "https://dummy",
			},
			checkFunc: func(got Option) error {
				c := &confd{}
				got(c)

				if c.athenzURL != "dummy" {
					return fmt.Errorf("cannot set athenz url")
				}
				return nil
			},
		},
		{
			name: "do not remove other protocol",
			args: args{
				athenzURL: "ftp://dummy",
			},
			checkFunc: func(got Option) error {
				c := &confd{}
				got(c)

				if c.athenzURL != "ftp://dummy" {
					return fmt.Errorf("cannot set athenz url")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AthenzURL(tt.args.athenzURL)
			if got == nil {
				t.Errorf("AthenzURL() = nil")
				return
			}
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("AthenzURL() = %v", err)
			}
		})
	}
}

func TestSysAuthDomain(t *testing.T) {
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
				c := &confd{}
				got(c)

				if c.sysAuthDomain != "dummy" {
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
				c := &confd{}
				got(c)
				if c.sysAuthDomain != "" {
					return fmt.Errorf("invalid domain wasset")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SysAuthDomain(tt.args.domain)
			if got == nil {
				t.Errorf("SysAuthDomain() = nil")
				return
			}
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("SysAuthDomain() = %v", err)
			}
		})
	}
}

func TestETagExpTime(t *testing.T) {
	type args struct {
		time string
	}
	tests := []struct {
		name      string
		args      args
		checkFunc func(Option) error
	}{
		{
			name: "set etag expire time success",
			args: args{
				time: "2h",
			},
			checkFunc: func(got Option) error {
				c := &confd{}
				got(c)

				if c.etagExpTime != time.Duration(time.Hour*2) {
					return fmt.Errorf("cannot set etag expire time")
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
				c := &confd{}
				got(c)
				if !reflect.DeepEqual(c, &confd{}) {
					return fmt.Errorf("expected no changes, but got %v", c)
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
				c := &confd{}
				err := got(c)

				if err == nil {
					return fmt.Errorf("invalid etag expire time was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ETagExpTime(tt.args.time)
			if got == nil {
				t.Errorf("ETagExpTime() = nil")
				return
			}
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("ETagExpTime() = %v", err)
			}
		})
	}
}

func TestErrRetryInterval(t *testing.T) {
	type args struct {
		time string
	}
	tests := []struct {
		name      string
		args      args
		checkFunc func(Option) error
	}{
		{
			name: "set errRetryInterval expire time success",
			args: args{
				time: "2h",
			},
			checkFunc: func(got Option) error {
				c := &confd{}
				got(c)

				if c.errRetryInterval != time.Duration(time.Hour*2) {
					return fmt.Errorf("cannot set errRetryInterval time")
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
				c := &confd{}
				got(c)
				if !reflect.DeepEqual(c, &confd{}) {
					return fmt.Errorf("expected no changes, but got %v", c)
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
				c := &confd{}
				err := got(c)

				if err == nil {
					return fmt.Errorf("invalid errRetryInterval time was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ErrRetryInterval(tt.args.time)
			if got == nil {
				t.Errorf("ErrRetryInterval() = nil")
				return
			}
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("ErrRetryInterval() = %v", err)
			}
		})
	}
}

func TestETagFlushDur(t *testing.T) {
	type args struct {
		dur string
	}
	tests := []struct {
		name      string
		args      args
		checkFunc func(Option) error
	}{
		{
			name: "set etag expire time success",
			args: args{
				dur: "2h",
			},
			checkFunc: func(got Option) error {
				c := &confd{}
				got(c)

				if c.etagFlushDur != time.Duration(time.Hour*2) {
					return fmt.Errorf("cannot set etag flush duration")
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
				c := &confd{}
				err := got(c)

				if err == nil {
					return fmt.Errorf("invalid etag flush duration was set")
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
				c := &confd{}
				got(c)
				if !reflect.DeepEqual(c, &confd{}) {
					return fmt.Errorf("expected no changes, but got %v", c)
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ETagFlushDur(tt.args.dur)
			if got == nil {
				t.Errorf("ETagFlushDur() = nil")
				return
			}
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("ETagFlushDur() = %v", err)
			}
		})
	}
}

func TestRefreshDuration(t *testing.T) {
	type args struct {
		dur string
	}
	tests := []struct {
		name      string
		args      args
		checkFunc func(Option) error
	}{
		{
			name: "set refresh duration success",
			args: args{
				dur: "2h",
			},
			checkFunc: func(got Option) error {
				c := &confd{}
				got(c)

				if c.refreshDuration != time.Duration(time.Hour*2) {
					return fmt.Errorf("cannot set refresh duration")
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
				c := &confd{}
				err := got(c)

				if err == nil {
					return fmt.Errorf("invalid refresh duration was set")
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
				c := &confd{}
				got(c)
				if !reflect.DeepEqual(c, &confd{}) {
					return fmt.Errorf("expected no changes, but got %v", c)
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RefreshDuration(tt.args.dur)
			if got == nil {
				t.Errorf("RefreshDuration() = nil")
				return
			}
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("RefreshDuration() = %v", err)
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
					cd := &confd{}
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
				cd := &confd{}
				if err := opt(cd); err != nil {
					return err
				}
				if !reflect.DeepEqual(cd, &confd{}) {
					return fmt.Errorf("expected no changes, but got %v", cd)
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
