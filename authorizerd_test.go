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
	"context"
	"crypto/x509"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/kpango/gache"
	"github.com/pkg/errors"
	"github.com/yahoojapan/athenz-authorizer/jwk"
	"github.com/yahoojapan/athenz-authorizer/policy"
	"github.com/yahoojapan/athenz-authorizer/pubkey"
	"github.com/yahoojapan/athenz-authorizer/role"
)

func TestNew(t *testing.T) {
	type args struct {
		opts []Option
	}
	tests := []struct {
		name      string
		args      args
		checkFunc func(Authorizerd, error) error
	}{
		{
			name: "test new success",
			args: args{
				[]Option{},
			},
			checkFunc: func(prov Authorizerd, err error) error {
				if err != nil {
					return errors.Wrap(err, "unexpected error")
				}
				if prov.(*authorizer).athenzURL != "www.athenz.com/zts/v1" {
					return errors.New("invalid url")
				}
				if prov.(*authorizer).pubkeyd == nil {
					return errors.New("cannot new pubkeyd")
				}
				if prov.(*authorizer).policyd == nil {
					return errors.New("cannot new policyd")
				}
				return nil
			},
		},
		{
			name: "test new success with options",
			args: args{
				[]Option{WithAthenzURL("www.dummy.com")},
			},
			checkFunc: func(prov Authorizerd, err error) error {
				if err != nil {
					return errors.Wrap(err, "unexpected error")
				}
				if prov.(*authorizer).athenzURL != "www.dummy.com" {
					return errors.New("invalid url")
				}
				return nil
			},
		},
		{
			name: "test New returns error",
			args: args{
				[]Option{WithPubkeyEtagExpTime("dummy")},
			},
			checkFunc: func(prov Authorizerd, err error) error {
				want := "error create pubkeyd: invalid etag expire time: time: invalid duration dummy"
				if err.Error() != want {
					return errors.Errorf("Unexpected error: %s, expected: %s", err, want)
				}
				return nil
			},
		},
		{
			name: "test NewPolicy returns error",
			args: args{
				[]Option{WithPolicyEtagExpTime("dummy")},
			},
			checkFunc: func(prov Authorizerd, err error) error {
				if err.Error() != "error create policyd: error create policyd: invalid etag expire time: time: invalid duration dummy" {
					return errors.Wrap(err, "unexpected error")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, goter := New(tt.args.opts...)
			if err := tt.checkFunc(got, goter); err != nil {
				t.Errorf("New() error = %v", err)
			}
		})
	}
}

func TestStart(t *testing.T) {
	type fields struct {
		pubkeyd  pubkey.Daemon
		policyd  policy.Daemon
		jwkd     jwk.Daemon
		cache    gache.Gache
		cacheExp time.Duration
	}
	type args struct {
		ctx context.Context
	}
	type test struct {
		name      string
		fields    fields
		args      args
		checkFunc func(Authorizerd, error) error
		afterFunc func()
	}
	tests := []test{
		func() test {
			ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Millisecond*10))
			cm := &ConfdMock{
				confdExp: time.Second,
			}
			pm := &PolicydMock{
				policydExp: time.Second,
			}
			jd := &JwkdMock{}
			return test{
				name: "test context done",
				fields: fields{
					pubkeyd:  cm,
					policyd:  pm,
					jwkd:     jd,
					cache:    gache.New(),
					cacheExp: time.Minute,
				},
				args: args{
					ctx: ctx,
				},
				checkFunc: func(prov Authorizerd, err error) error {
					if err.Error() != "context deadline exceeded" {
						return errors.Wrap(err, "unexpected err")
					}
					return nil
				},
				afterFunc: func() {
					cancel()
				},
			}
		}(),
		func() test {
			ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Second))
			cm := &ConfdMock{
				confdExp: time.Millisecond * 10,
			}
			pm := &PolicydMock{
				policydExp: time.Second,
			}
			jd := &JwkdMock{}
			return test{
				name: "test context pubkey updater returns error",
				fields: fields{
					pubkeyd:  cm,
					policyd:  pm,
					jwkd:     jd,
					cache:    gache.New(),
					cacheExp: time.Minute,
				},
				args: args{
					ctx: ctx,
				},
				checkFunc: func(prov Authorizerd, err error) error {
					if err.Error() != "update pubkey error: pubkey error" {
						return errors.Wrap(err, "unexpected err")
					}
					return nil
				},
				afterFunc: func() {
					cancel()
				},
			}
		}(),
		func() test {
			ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Second))
			cm := &ConfdMock{
				confdExp: time.Second,
			}
			pm := &PolicydMock{
				policydExp: time.Millisecond * 10,
			}
			jd := &JwkdMock{}
			return test{
				name: "test policyd returns error",
				fields: fields{
					pubkeyd:  cm,
					policyd:  pm,
					jwkd:     jd,
					cache:    gache.New(),
					cacheExp: time.Minute,
				},
				args: args{
					ctx: ctx,
				},
				checkFunc: func(prov Authorizerd, err error) error {
					if err.Error() != "update policy error: policyd error" {
						return errors.Wrap(err, "unexpected err")
					}
					return nil
				},
				afterFunc: func() {
					cancel()
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prov := &authorizer{
				pubkeyd:  tt.fields.pubkeyd,
				policyd:  tt.fields.policyd,
				jwkd:     tt.fields.jwkd,
				cache:    tt.fields.cache,
				cacheExp: tt.fields.cacheExp,
			}
			ch := prov.Start(tt.args.ctx)
			goter := <-ch
			if err := tt.checkFunc(prov, goter); err != nil {
				t.Errorf("Start() error = %v", err)
			}
			tt.afterFunc()
		})
	}
}

func TestVerifyRoleToken(t *testing.T) {
	type args struct {
		ctx context.Context
		tok string
		act string
		res string
	}
	type fields struct {
		policyd            policy.Daemon
		cache              gache.Gache
		cacheExp           time.Duration
		roleTokenProcessor role.Processor
	}
	type test struct {
		name      string
		args      args
		fields    fields
		wantErr   string
		checkFunc func(*authorizer) error
	}
	tests := []test{
		func() test {
			c := gache.New()
			rm := &TokenMock{
				rt:      &role.Token{},
				wantErr: nil,
			}
			cm := &PolicydMock{
				wantErr: nil,
			}
			return test{
				name: "test verify success",
				args: args{
					ctx: context.Background(),
					tok: "dummyTok",
					act: "dummyAct",
					res: "dummyRes",
				},
				fields: fields{
					policyd:            cm,
					roleTokenProcessor: rm,
					cache:              c,
					cacheExp:           time.Minute,
				},
				wantErr: "",
				checkFunc: func(prov *authorizer) error {
					_, ok := prov.cache.Get("dummyTokdummyActdummyRes")
					if !ok {
						return errors.New("cannot get dummyTokdummyActdummyRes from cache")
					}
					return nil
				},
			}
		}(),
		func() test {
			c := gache.New()
			c.Set("dummyTokdummyActdummyRes", "dummy")
			rm := &TokenMock{
				rt:      &role.Token{},
				wantErr: nil,
			}
			cm := &PolicydMock{
				wantErr: nil,
			}
			return test{
				name: "test use cache success",
				args: args{
					ctx: context.Background(),
					tok: "dummyTok",
					act: "dummyAct",
					res: "dummyRes",
				},
				fields: fields{
					policyd:            cm,
					roleTokenProcessor: rm,
					cache:              c,
					cacheExp:           time.Minute,
				},
				wantErr: "",
			}
		}(),
		func() test {
			c := gache.New()
			c.Set("dummyTokdummyActdummyRes", "dummy")
			rm := &TokenMock{
				rt:      &role.Token{},
				wantErr: nil,
			}
			cm := &PolicydMock{
				wantErr: nil,
			}
			return test{
				name: "test empty action",
				args: args{
					ctx: context.Background(),
					tok: "dummyTok",
					act: "",
					res: "dummyRes",
				},
				fields: fields{
					policyd:            cm,
					roleTokenProcessor: rm,
					cache:              c,
					cacheExp:           time.Minute,
				},
				wantErr: "empty action / resource: Access denied due to invalid/empty action/resource values",
			}
		}(),
		func() test {
			c := gache.New()
			c.Set("dummyTokdummyActdummyRes", "dummy")
			rm := &TokenMock{
				rt:      &role.Token{},
				wantErr: nil,
			}
			cm := &PolicydMock{
				wantErr: nil,
			}
			return test{
				name: "test empty res",
				args: args{
					ctx: context.Background(),
					tok: "dummyTok",
					act: "dummyAct",
					res: "",
				},
				fields: fields{
					policyd:            cm,
					roleTokenProcessor: rm,
					cache:              c,
					cacheExp:           time.Minute,
				},
				wantErr: "empty action / resource: Access denied due to invalid/empty action/resource values",
			}
		}(),
		func() test {
			c := gache.New()
			rm := &TokenMock{
				wantErr: errors.New("cannot parse roletoken"),
			}
			cm := &PolicydMock{}
			return test{
				name: "test parse roletoken error",
				args: args{
					ctx: context.Background(),
					tok: "dummyTok",
					act: "dummyAct",
					res: "dummyRes",
				},
				fields: fields{
					policyd:            cm,
					roleTokenProcessor: rm,
					cache:              c,
					cacheExp:           time.Minute,
				},
				wantErr: "error verify role token: cannot parse roletoken",
			}
		}(),
		func() test {
			c := gache.New()
			rm := &TokenMock{
				rt: &role.Token{},
			}
			cm := &PolicydMock{
				wantErr: errors.New("deny"),
			}
			return test{
				name: "test return deny",
				args: args{
					ctx: context.Background(),
					tok: "dummyTok",
					act: "dummyAct",
					res: "dummyRes",
				},
				fields: fields{
					policyd:            cm,
					roleTokenProcessor: rm,
					cache:              c,
					cacheExp:           time.Minute,
				},
				wantErr: "token unauthorizate: deny",
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prov := &authorizer{
				policyd:       tt.fields.policyd,
				roleProcessor: tt.fields.roleTokenProcessor,
				cache:         tt.fields.cache,
				cacheExp:      tt.fields.cacheExp,
			}
			err := prov.VerifyRoleToken(tt.args.ctx, tt.args.tok, tt.args.act, tt.args.res)
			if err != nil {
				if err.Error() != tt.wantErr {
					t.Errorf("VerifyRoleToken() unexpected error want:%s, result:%s", tt.wantErr, err.Error())
					return
				}
			} else {
				if tt.wantErr != "" {
					t.Errorf("VerifyRoleToken() return nil. want %s", tt.wantErr)
					return
				}
			}
			if tt.checkFunc != nil {
				if err := tt.checkFunc(prov); err != nil {
					t.Errorf("VerifyRoleToken() error: %v", err)
				}
			}
		})
	}
}

func Test_authorizer_VerifyRoleJWT(t *testing.T) {
	type fields struct {
		pubkeyd               pubkey.Daemon
		policyd               policy.Daemon
		jwkd                  jwk.Daemon
		roleProcessor         role.Processor
		athenzURL             string
		client                *http.Client
		cache                 gache.Gache
		cacheExp              time.Duration
		roleCertURIPrefix     string
		pubkeyRefreshDuration string
		pubkeySysAuthDomain   string
		pubkeyEtagExpTime     string
		pubkeyEtagFlushDur    string
		policyExpireMargin    string
		athenzDomains         []string
		policyRefreshDuration string
		policyEtagFlushDur    string
		policyEtagExpTime     string
	}
	type args struct {
		ctx context.Context
		tok string
		act string
		res string
	}
	type test struct {
		name      string
		args      args
		fields    fields
		wantErr   string
		checkFunc func(*authorizer) error
	}
	tests := []test{
		func() test {
			c := gache.New()
			rm := &TokenMock{
				c:       &role.Claim{},
				wantErr: nil,
			}
			cm := &PolicydMock{
				wantErr: nil,
			}
			return test{
				name: "test verify success",
				args: args{
					ctx: context.Background(),
					tok: "dummyTok",
					act: "dummyAct",
					res: "dummyRes",
				},
				fields: fields{
					policyd:       cm,
					roleProcessor: rm,
					cache:         c,
					cacheExp:      time.Minute,
				},
				wantErr: "",
				checkFunc: func(prov *authorizer) error {
					_, ok := prov.cache.Get("dummyTokdummyActdummyRes")
					if !ok {
						return errors.New("cannot get dummyTokdummyActdummyRes from cache")
					}
					return nil
				},
			}
		}(),
		func() test {
			c := gache.New()
			c.Set("dummyTokdummyActdummyRes", "dummy")
			rm := &TokenMock{
				c:       &role.Claim{},
				wantErr: nil,
			}
			cm := &PolicydMock{
				wantErr: nil,
			}
			return test{
				name: "test use cache success",
				args: args{
					ctx: context.Background(),
					tok: "dummyTok",
					act: "dummyAct",
					res: "dummyRes",
				},
				fields: fields{
					policyd:       cm,
					roleProcessor: rm,
					cache:         c,
					cacheExp:      time.Minute,
				},
				wantErr: "",
			}
		}(),
		func() test {
			c := gache.New()
			c.Set("dummyTokdummyActdummyRes", "dummy")
			rm := &TokenMock{
				c:       &role.Claim{},
				wantErr: nil,
			}
			cm := &PolicydMock{
				wantErr: nil,
			}
			return test{
				name: "test empty action",
				args: args{
					ctx: context.Background(),
					tok: "dummyTok",
					act: "",
					res: "dummyRes",
				},
				fields: fields{
					policyd:       cm,
					roleProcessor: rm,
					cache:         c,
					cacheExp:      time.Minute,
				},
				wantErr: "empty action / resource: Access denied due to invalid/empty action/resource values",
			}
		}(),
		func() test {
			c := gache.New()
			c.Set("dummyTokdummyActdummyRes", "dummy")
			rm := &TokenMock{
				c:       &role.Claim{},
				wantErr: nil,
			}
			cm := &PolicydMock{
				wantErr: nil,
			}
			return test{
				name: "test empty res",
				args: args{
					ctx: context.Background(),
					tok: "dummyTok",
					act: "dummyAct",
					res: "",
				},
				fields: fields{
					policyd:       cm,
					roleProcessor: rm,
					cache:         c,
					cacheExp:      time.Minute,
				},
				wantErr: "empty action / resource: Access denied due to invalid/empty action/resource values",
			}
		}(),
		func() test {
			c := gache.New()
			rm := &TokenMock{
				wantErr: errors.New("cannot parse role jwt"),
			}
			cm := &PolicydMock{}
			return test{
				name: "test parse role jwt error",
				args: args{
					ctx: context.Background(),
					tok: "dummyTok",
					act: "dummyAct",
					res: "dummyRes",
				},
				fields: fields{
					policyd:       cm,
					roleProcessor: rm,
					cache:         c,
					cacheExp:      time.Minute,
				},
				wantErr: "error verify role jwt: cannot parse role jwt",
			}
		}(),
		func() test {
			c := gache.New()
			rm := &TokenMock{
				c: &role.Claim{},
			}
			cm := &PolicydMock{
				wantErr: errors.New("deny"),
			}
			return test{
				name: "test return deny",
				args: args{
					ctx: context.Background(),
					tok: "dummyTok",
					act: "dummyAct",
					res: "dummyRes",
				},
				fields: fields{
					policyd:       cm,
					roleProcessor: rm,
					cache:         c,
					cacheExp:      time.Minute,
				},
				wantErr: "token unauthorizate: deny",
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &authorizer{
				pubkeyd:               tt.fields.pubkeyd,
				policyd:               tt.fields.policyd,
				jwkd:                  tt.fields.jwkd,
				roleProcessor:         tt.fields.roleProcessor,
				athenzURL:             tt.fields.athenzURL,
				client:                tt.fields.client,
				cache:                 tt.fields.cache,
				cacheExp:              tt.fields.cacheExp,
				roleCertURIPrefix:     tt.fields.roleCertURIPrefix,
				pubkeyRefreshDuration: tt.fields.pubkeyRefreshDuration,
				pubkeySysAuthDomain:   tt.fields.pubkeySysAuthDomain,
				pubkeyEtagExpTime:     tt.fields.pubkeyEtagExpTime,
				pubkeyEtagFlushDur:    tt.fields.pubkeyEtagFlushDur,
				policyExpireMargin:    tt.fields.policyExpireMargin,
				athenzDomains:         tt.fields.athenzDomains,
				policyRefreshDuration: tt.fields.policyRefreshDuration,
				policyEtagFlushDur:    tt.fields.policyEtagFlushDur,
				policyEtagExpTime:     tt.fields.policyEtagExpTime,
			}
			err := p.VerifyRoleJWT(tt.args.ctx, tt.args.tok, tt.args.act, tt.args.res)
			if err != nil {
				if err.Error() != tt.wantErr {
					t.Errorf("VerifyRoleJWT() unexpected error want:%s, result:%s", tt.wantErr, err.Error())
					return
				}
			} else {
				if tt.wantErr != "" {
					t.Errorf("VerifyRoleJWT() return nil. want %s", tt.wantErr)
					return
				}
			}
			if tt.checkFunc != nil {
				if err := tt.checkFunc(p); err != nil {
					t.Errorf("VerifyRoleJWT() error: %v", err)
				}
			}
		})
	}
}

func Test_authorizer_verify(t *testing.T) {
	type fields struct {
		pubkeyd               pubkey.Daemon
		policyd               policy.Daemon
		jwkd                  jwk.Daemon
		roleProcessor         role.Processor
		athenzURL             string
		client                *http.Client
		cache                 gache.Gache
		cacheExp              time.Duration
		roleCertURIPrefix     string
		pubkeyRefreshDuration string
		pubkeySysAuthDomain   string
		pubkeyEtagExpTime     string
		pubkeyEtagFlushDur    string
		policyExpireMargin    string
		athenzDomains         []string
		policyRefreshDuration string
		policyEtagFlushDur    string
		policyEtagExpTime     string
	}
	type args struct {
		ctx context.Context
		m   mode
		tok string
		act string
		res string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &authorizer{
				pubkeyd:               tt.fields.pubkeyd,
				policyd:               tt.fields.policyd,
				jwkd:                  tt.fields.jwkd,
				roleProcessor:         tt.fields.roleProcessor,
				athenzURL:             tt.fields.athenzURL,
				client:                tt.fields.client,
				cache:                 tt.fields.cache,
				cacheExp:              tt.fields.cacheExp,
				roleCertURIPrefix:     tt.fields.roleCertURIPrefix,
				pubkeyRefreshDuration: tt.fields.pubkeyRefreshDuration,
				pubkeySysAuthDomain:   tt.fields.pubkeySysAuthDomain,
				pubkeyEtagExpTime:     tt.fields.pubkeyEtagExpTime,
				pubkeyEtagFlushDur:    tt.fields.pubkeyEtagFlushDur,
				policyExpireMargin:    tt.fields.policyExpireMargin,
				athenzDomains:         tt.fields.athenzDomains,
				policyRefreshDuration: tt.fields.policyRefreshDuration,
				policyEtagFlushDur:    tt.fields.policyEtagFlushDur,
				policyEtagExpTime:     tt.fields.policyEtagExpTime,
			}
			if err := p.verify(tt.args.ctx, tt.args.m, tt.args.tok, tt.args.act, tt.args.res); (err != nil) != tt.wantErr {
				t.Errorf("authorizer.verify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_authorizer_VerifyRoleCert(t *testing.T) {
	type fields struct {
		pubkeyd               pubkey.Daemon
		policyd               policy.Daemon
		jwkd                  jwk.Daemon
		roleProcessor         role.Processor
		athenzURL             string
		client                *http.Client
		cache                 gache.Gache
		cacheExp              time.Duration
		roleCertURIPrefix     string
		pubkeyRefreshDuration string
		pubkeySysAuthDomain   string
		pubkeyEtagExpTime     string
		pubkeyEtagFlushDur    string
		policyExpireMargin    string
		athenzDomains         []string
		policyRefreshDuration string
		policyEtagFlushDur    string
		policyEtagExpTime     string
	}
	type args struct {
		ctx       context.Context
		peerCerts []*x509.Certificate
		act       string
		res       string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &authorizer{
				pubkeyd:               tt.fields.pubkeyd,
				policyd:               tt.fields.policyd,
				jwkd:                  tt.fields.jwkd,
				roleProcessor:         tt.fields.roleProcessor,
				athenzURL:             tt.fields.athenzURL,
				client:                tt.fields.client,
				cache:                 tt.fields.cache,
				cacheExp:              tt.fields.cacheExp,
				roleCertURIPrefix:     tt.fields.roleCertURIPrefix,
				pubkeyRefreshDuration: tt.fields.pubkeyRefreshDuration,
				pubkeySysAuthDomain:   tt.fields.pubkeySysAuthDomain,
				pubkeyEtagExpTime:     tt.fields.pubkeyEtagExpTime,
				pubkeyEtagFlushDur:    tt.fields.pubkeyEtagFlushDur,
				policyExpireMargin:    tt.fields.policyExpireMargin,
				athenzDomains:         tt.fields.athenzDomains,
				policyRefreshDuration: tt.fields.policyRefreshDuration,
				policyEtagFlushDur:    tt.fields.policyEtagFlushDur,
				policyEtagExpTime:     tt.fields.policyEtagExpTime,
			}
			if err := p.VerifyRoleCert(tt.args.ctx, tt.args.peerCerts, tt.args.act, tt.args.res); (err != nil) != tt.wantErr {
				t.Errorf("authorizer.VerifyRoleCert() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_authorizer_GetPolicyCache(t *testing.T) {
	type fields struct {
		pubkeyd               pubkey.Daemon
		policyd               policy.Daemon
		jwkd                  jwk.Daemon
		roleProcessor         role.Processor
		athenzURL             string
		client                *http.Client
		cache                 gache.Gache
		cacheExp              time.Duration
		roleCertURIPrefix     string
		pubkeyRefreshDuration string
		pubkeySysAuthDomain   string
		pubkeyEtagExpTime     string
		pubkeyEtagFlushDur    string
		policyExpireMargin    string
		athenzDomains         []string
		policyRefreshDuration string
		policyEtagFlushDur    string
		policyEtagExpTime     string
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   map[string]interface{}
	}{
		{
			name: "GetPolicyCache success",
			fields: fields{
				policyd: &PolicydMock{},
			},
			args: args{
				ctx: context.Background(),
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &authorizer{
				pubkeyd:               tt.fields.pubkeyd,
				policyd:               tt.fields.policyd,
				jwkd:                  tt.fields.jwkd,
				roleProcessor:         tt.fields.roleProcessor,
				athenzURL:             tt.fields.athenzURL,
				client:                tt.fields.client,
				cache:                 tt.fields.cache,
				cacheExp:              tt.fields.cacheExp,
				roleCertURIPrefix:     tt.fields.roleCertURIPrefix,
				pubkeyRefreshDuration: tt.fields.pubkeyRefreshDuration,
				pubkeySysAuthDomain:   tt.fields.pubkeySysAuthDomain,
				pubkeyEtagExpTime:     tt.fields.pubkeyEtagExpTime,
				pubkeyEtagFlushDur:    tt.fields.pubkeyEtagFlushDur,
				policyExpireMargin:    tt.fields.policyExpireMargin,
				athenzDomains:         tt.fields.athenzDomains,
				policyRefreshDuration: tt.fields.policyRefreshDuration,
				policyEtagFlushDur:    tt.fields.policyEtagFlushDur,
				policyEtagExpTime:     tt.fields.policyEtagExpTime,
			}
			if got := a.GetPolicyCache(tt.args.ctx); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("authorizer.GetPolicyCache() = %v, want %v", got, tt.want)
			}
		})
	}
}
