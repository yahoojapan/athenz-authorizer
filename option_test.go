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
)

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
				prov := &authorizer{}
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
				prov := &authorizer{}
				if err := opt(prov); err != nil {
					return err
				}
				if prov.pubkeyRefreshDuration != "dummy" {
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
func TestWithAthenzURL(t *testing.T) {
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
				prov := &authorizer{}
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
			got := WithAthenzURL(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithAthenzURL() error = %v", err)
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
				prov := &authorizer{}
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
				prov := &authorizer{}
				if err := opt(prov); err != nil {
					return err
				}
				if prov.pubkeySysAuthDomain != "dummy" {
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
				prov := &authorizer{}
				if err := opt(prov); err != nil {
					return err
				}
				if prov.pubkeyEtagExpTime != "dummy" {
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
				prov := &authorizer{}
				if err := opt(prov); err != nil {
					return err
				}
				if prov.pubkeyEtagFlushDur != "dummy" {
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
				prov := &authorizer{}
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
			got := WithPolicyExpireMargin(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithPolicyExpireMargin() error = %v", err)
			}
		})
	}
}
func TestWithPolicyEtagFlushDuration(t *testing.T) {
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
				prov := &authorizer{}
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
			got := WithPolicyEtagFlushDuration(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithPolicyEtagFlushDuration() error = %v", err)
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
				prov := &authorizer{}
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
			got := WithPolicyEtagExpTime(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithPolicyEtagExpTime() error = %v", err)
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
				prov := &authorizer{
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
			got := WithCacheExp(tt.args.d)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithCacheExp() error = %v", err)
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
				prov := &authorizer{}
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
				prov := &authorizer{}
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
			got := WithTransport(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithTransport() error = %v", err)
			}
		})
	}
}
