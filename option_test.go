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
package providerd

import (
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/kpango/gache"
)

func TestPolicyRefreshDuration(t *testing.T) {
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
				prov := &provider{}
				if err := opt(prov); err != nil {
					return err
				}
				if prov.policyRefreshDuration != "dummy" {
					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PolicyRefreshDuration(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("PolicyRefreshDuration() error = %v", err)
			}
		})
	}
}
func TestAthenzConfRefreshDuration(t *testing.T) {
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
				prov := &provider{}
				if err := opt(prov); err != nil {
					return err
				}
				if prov.athenzConfRefreshDuration != "dummy" {
					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AthenzConfRefreshDuration(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("AthenzConfRefreshDuration() error = %v", err)
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
				t: "dummy",
			},
			checkFunc: func(opt Option) error {
				prov := &provider{}
				if err := opt(prov); err != nil {
					return err
				}
				if prov.athenzURL != "dummy" {
					return fmt.Errorf("invalid param was set")
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
				t: []string{"dummy1", "dummy2"},
			},
			checkFunc: func(opt Option) error {
				prov := &provider{}
				if err := opt(prov); err != nil {
					return err
				}
				if !reflect.DeepEqual(prov.athenzDomains, []string{"dummy1", "dummy2"}) {
					return fmt.Errorf("invalid param was set")
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
func TestAthenzConfSysAuthDomain(t *testing.T) {
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
				prov := &provider{}
				if err := opt(prov); err != nil {
					return err
				}
				if prov.athenzConfSysAuthDomain != "dummy" {
					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AthenzConfSysAuthDomain(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("AthenzConfSysAuthDomain() error = %v", err)
			}
		})
	}
}
func TestAthenzConfEtagExpTime(t *testing.T) {
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
				prov := &provider{}
				if err := opt(prov); err != nil {
					return err
				}
				if prov.athenzConfEtagExpTime != "dummy" {
					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AthenzConfEtagExpTime(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("AthenzConfEtagExpTime() error = %v", err)
			}
		})
	}
}
func TestAthenzConfEtagFlushDur(t *testing.T) {
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
				prov := &provider{}
				if err := opt(prov); err != nil {
					return err
				}
				if prov.athenzConfEtagFlushDur != "dummy" {
					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AthenzConfEtagFlushDur(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("AthenzConfEtagFlushDur() error = %v", err)
			}
		})
	}
}
func TestPolicyExpireMargin(t *testing.T) {
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
				prov := &provider{}
				if err := opt(prov); err != nil {
					return err
				}
				if prov.policyExpireMargin != "dummy" {
					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PolicyExpireMargin(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("PolicyExpireMargin() error = %v", err)
			}
		})
	}
}
func TestPolicyEtagFlushDur(t *testing.T) {
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
				prov := &provider{}
				if err := opt(prov); err != nil {
					return err
				}
				if prov.policyEtagFlushDur != "dummy" {
					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PolicyEtagFlushDur(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("PolicyEtagFlushDur() error = %v", err)
			}
		})
	}
}
func TestPolicyEtagExpTime(t *testing.T) {
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
				prov := &provider{}
				if err := opt(prov); err != nil {
					return err
				}
				if prov.policyEtagExpTime != "dummy" {
					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PolicyEtagExpTime(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("PolicyEtagExpTime() error = %v", err)
			}
		})
	}
}
func TestCacheExp(t *testing.T) {
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
				prov := &provider{
					cache: gache.New(),
				}
				if err := opt(prov); err != nil {
					return err
				}
				if prov.cacheExp != time.Duration(time.Hour*2) {
					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CacheExp(tt.args.d)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("CacheExp() error = %v", err)
			}
		})
	}
}
func TestTransport(t *testing.T) {
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
				prov := &provider{}
				if err := opt(prov); err != nil {
					return err
				}
				if !reflect.DeepEqual(prov.client.Transport, &http.Transport{}) {
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
				prov := &provider{}
				if err := opt(prov); err != nil {
					return err
				}
				want := &http.Client{
					Timeout: time.Second * 30,
				}
				if !reflect.DeepEqual(prov.client, want) {
					return fmt.Errorf("invalid param was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Transport(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("Transport() error = %v", err)
			}
		})
	}
}
