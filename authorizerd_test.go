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
	"encoding/pem"
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"

	jwtgo "github.com/dgrijalva/jwt-go"
	"github.com/kpango/fastime"
	"github.com/kpango/gache"
	"github.com/pkg/errors"
	"github.com/yahoojapan/athenz-authorizer/v2/jwk"
	"github.com/yahoojapan/athenz-authorizer/v2/policy"
	"github.com/yahoojapan/athenz-authorizer/v2/pubkey"
	"github.com/yahoojapan/athenz-authorizer/v2/role"
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
				if prov.(*authorizer).athenzURL != "athenz.io/zts/v1" {
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

func Test_authorizer_initVerifiers(t *testing.T) {
	type fields struct {
		verifiers              []verifier
		athenzURL              string
		client                 *http.Client
		cache                  gache.Gache
		cacheExp               time.Duration
		roleCertURIPrefix      string
		disablePubkeyd         bool
		pubkeyRefreshDuration  string
		pubkeyErrRetryInterval string
		pubkeySysAuthDomain    string
		pubkeyEtagExpTime      string
		pubkeyEtagFlushDur     string
		disablePolicyd         bool
		policyExpireMargin     string
		athenzDomains          []string
		policyRefreshDuration  string
		policyErrRetryInterval string
		disableJwkd            bool
		jwkRefreshDuration     string
		jwkErrRetryInterval    string
		atpParam               ATProcessorParam
		verifyRoleToken        bool
		rtHeader               string
		verifyRoleCert         bool
	}
	tests := []struct {
		name      string
		fields    fields
		wantErr   bool
		checkFunc func(a authorizer) error
	}{
		{
			name: "initVerifier sucess, no role flags",
			fields: fields{
				atpParam:        ATProcessorParam{verifyOAuth2AccessToken: true, verifyCertThumbprint: true},
				verifyRoleCert:  false,
				verifyRoleToken: false,
			},
			wantErr: false,
			checkFunc: func(a authorizer) error {
				if len(a.verifiers) != 1 {
					return errors.New("failed init verifier")
				}
				return nil
			},
		},
		{
			name: "initVerifier sucess, no access token flags",
			fields: fields{
				verifyRoleCert: true,
			},
			wantErr: false,
			checkFunc: func(a authorizer) error {
				if len(a.verifiers) != 1 {
					return errors.New("failed init verifier")
				}
				return nil
			},
		},
		{
			name: "initVerifier sucess, no access token flags",
			fields: fields{
				verifyRoleCert:  true,
				verifyRoleToken: true,
			},
			wantErr: false,
			checkFunc: func(a authorizer) error {
				if len(a.verifiers) != 2 {
					return errors.New("failed init verifier")
				}
				return nil
			},
		},
		{
			name:    "initVerifier fail, no verifiers",
			fields:  fields{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &authorizer{
				verifiers:              tt.fields.verifiers,
				athenzURL:              tt.fields.athenzURL,
				client:                 tt.fields.client,
				cache:                  tt.fields.cache,
				cacheExp:               tt.fields.cacheExp,
				roleCertURIPrefix:      tt.fields.roleCertURIPrefix,
				disablePubkeyd:         tt.fields.disablePubkeyd,
				pubkeyRefreshDuration:  tt.fields.pubkeyRefreshDuration,
				pubkeyErrRetryInterval: tt.fields.pubkeyErrRetryInterval,
				pubkeySysAuthDomain:    tt.fields.pubkeySysAuthDomain,
				pubkeyEtagExpTime:      tt.fields.pubkeyEtagExpTime,
				pubkeyEtagFlushDur:     tt.fields.pubkeyEtagFlushDur,
				disablePolicyd:         tt.fields.disablePolicyd,
				policyExpireMargin:     tt.fields.policyExpireMargin,
				athenzDomains:          tt.fields.athenzDomains,
				policyRefreshDuration:  tt.fields.policyRefreshDuration,
				policyErrRetryInterval: tt.fields.policyErrRetryInterval,
				disableJwkd:            tt.fields.disableJwkd,
				jwkRefreshDuration:     tt.fields.jwkRefreshDuration,
				jwkErrRetryInterval:    tt.fields.jwkErrRetryInterval,
				atpParam:               tt.fields.atpParam,
				verifyRoleToken:        tt.fields.verifyRoleToken,
				rtHeader:               tt.fields.rtHeader,
				verifyRoleCert:         tt.fields.verifyRoleCert,
			}
			if err := a.initVerifiers(); (err != nil) != tt.wantErr {
				t.Errorf("authorizer.initVerifiers() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.checkFunc != nil {
				if err := tt.checkFunc(*a); err != nil {
					t.Errorf("VerifyRoleToken() error: %v", err)
				}
			}
		})
	}
}
func Test_authorizer_Init(t *testing.T) {
	type fields struct {
		pubkeyd        pubkey.Daemon
		policyd        policy.Daemon
		jwkd           jwk.Daemon
		disablePubkeyd bool
		disablePolicyd bool
		disableJwkd    bool
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name       string
		fields     fields
		args       args
		wantErrStr string
	}{
		{
			name: "cancelled context, no waiting",
			fields: fields{
				pubkeyd: &PubkeydMock{
					UpdateFunc: func(context.Context) error {
						time.Sleep(10 * time.Millisecond)
						return errors.New("pubkeyd error")
					},
				},
				policyd: nil,
				jwkd: &JwkdMock{
					UpdateFunc: func(context.Context) error {
						time.Sleep(10 * time.Millisecond)
						return errors.New("jwkd error")
					},
				},
				disablePubkeyd: false,
				disablePolicyd: true,
				disableJwkd:    false,
			},
			args: args{
				ctx: func() context.Context {
					ctx, cancel := context.WithCancel(context.Background())
					cancel()
					return ctx
				}(),
			},
			wantErrStr: context.Canceled.Error(),
		},
		{
			name: "all disable",
			fields: fields{
				pubkeyd:        nil,
				policyd:        nil,
				jwkd:           nil,
				disablePubkeyd: true,
				disablePolicyd: true,
				disableJwkd:    true,
			},
			args: args{
				ctx: context.Background(),
			},
			wantErrStr: "",
		},
		{
			name: "jwkd is not blocked",
			fields: fields{
				pubkeyd: &PubkeydMock{
					UpdateFunc: func(context.Context) error {
						time.Sleep(10 * time.Millisecond)
						return errors.New("pubkeyd error")
					},
				},
				policyd: nil,
				jwkd: &JwkdMock{
					UpdateFunc: func(context.Context) error {
						return errors.New("jwkd done")
					},
				},
				disablePubkeyd: false,
				disablePolicyd: true,
				disableJwkd:    false,
			},
			args: args{
				ctx: context.Background(),
			},
			wantErrStr: "jwkd done",
		},
		{
			name: "policyd is blocked by pubkeyd",
			fields: *(func() *fields {
				pubkeydDone := false
				return &fields{
					pubkeyd: &PubkeydMock{
						UpdateFunc: func(context.Context) error {
							time.Sleep(10 * time.Millisecond)
							pubkeydDone = true
							return nil
						},
					},
					policyd: &PolicydMock{
						UpdateFunc: func(context.Context) error {
							if pubkeydDone {
								return nil
							}
							return errors.New("policyd error")
						},
					},
					jwkd:           nil,
					disablePubkeyd: false,
					disablePolicyd: true,
					disableJwkd:    true,
				}
			}()),
			args: args{
				ctx: context.Background(),
			},
			wantErrStr: "",
		},
		{
			name: "all daemons init success",
			fields: fields{
				pubkeyd: &PubkeydMock{
					UpdateFunc: func(context.Context) error {
						return nil
					},
				},
				policyd: &PolicydMock{
					UpdateFunc: func(context.Context) error {
						return nil
					},
				},
				jwkd: &JwkdMock{
					UpdateFunc: func(context.Context) error {
						return nil
					},
				},
				disablePubkeyd: false,
				disablePolicyd: false,
				disableJwkd:    false,
			},
			args: args{
				ctx: context.Background(),
			},
			wantErrStr: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &authorizer{
				pubkeyd:        tt.fields.pubkeyd,
				policyd:        tt.fields.policyd,
				jwkd:           tt.fields.jwkd,
				disablePubkeyd: tt.fields.disablePubkeyd,
				disablePolicyd: tt.fields.disablePolicyd,
				disableJwkd:    tt.fields.disableJwkd,
			}
			err := a.Init(tt.args.ctx)
			if (err == nil && tt.wantErrStr != "") || (err != nil && err.Error() != tt.wantErrStr) {
				t.Errorf("authorizer.Init() error = %v, wantErr %v", err, tt.wantErrStr)
				return
			}
		})
	}
}

func Test_authorizer_Start(t *testing.T) {
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
			ctx, cancel := context.WithDeadline(context.Background(), fastime.Now().Add(time.Millisecond*10))
			pdm := &ConfdMock{
				confdExp: time.Second,
			}
			pm := &PolicydMock{
				policydExp: time.Second,
			}
			jd := &JwkdMock{}
			return test{
				name: "test context done",
				fields: fields{
					pubkeyd:  pdm,
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
			ctx, cancel := context.WithDeadline(context.Background(), fastime.Now().Add(time.Second))
			pdm := &ConfdMock{
				confdExp: time.Millisecond * 10,
			}
			pm := &PolicydMock{
				policydExp: time.Second,
			}
			jd := &JwkdMock{}
			return test{
				name: "test context pubkey updater returns error",
				fields: fields{
					pubkeyd:  pdm,
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
			ctx, cancel := context.WithDeadline(context.Background(), fastime.Now().Add(time.Second))
			pdm := &ConfdMock{
				confdExp: time.Second,
			}
			pm := &PolicydMock{
				policydExp: time.Millisecond * 10,
			}
			jd := &JwkdMock{}
			return test{
				name: "test policyd returns error",
				fields: fields{
					pubkeyd:  pdm,
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
		func() test {
			ctx, cancel := context.WithDeadline(context.Background(), fastime.Now().Add(time.Millisecond*500))
			pdm := &ConfdMock{
				confdExp: time.Second,
			}
			pm := &PolicydMock{
				policydExp: time.Second,
			}
			jd := &JwkdMock{
				StartFunc: func(ctx context.Context) <-chan error {
					ch := make(chan error, 1)
					go func() {
						time.Sleep(time.Millisecond * 20)
						ch <- errors.New("dummy")
					}()
					return ch
				},
			}
			return test{
				name: "test jwkd returns error",
				fields: fields{
					pubkeyd:  pdm,
					policyd:  pm,
					jwkd:     jd,
					cache:    gache.New(),
					cacheExp: time.Minute,
				},
				args: args{
					ctx: ctx,
				},
				checkFunc: func(prov Authorizerd, err error) error {
					if err.Error() != "update jwk error: dummy" {
						return errors.Errorf("unexpected error: %s", err)
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

func Test_authorizer_VerifyRoleToken(t *testing.T) {
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
			pm := &ProcessorMock{
				rt:      &role.Token{},
				wantErr: nil,
			}
			pdm := &PolicydMock{}
			return test{
				name: "test verify success",
				args: args{
					ctx: context.Background(),
					tok: "dummyTok",
					act: "dummyAct",
					res: "dummyRes",
				},
				fields: fields{
					policyd:            pdm,
					roleTokenProcessor: pm,
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
			pm := &ProcessorMock{
				rt:      &role.Token{},
				wantErr: nil,
			}
			pdm := &PolicydMock{}
			return test{
				name: "test use cache success",
				args: args{
					ctx: context.Background(),
					tok: "dummyTok",
					act: "dummyAct",
					res: "dummyRes",
				},
				fields: fields{
					policyd:            pdm,
					roleTokenProcessor: pm,
					cache:              c,
					cacheExp:           time.Minute,
				},
				wantErr: "",
			}
		}(),
		func() test {
			c := gache.New()
			c.Set("dummyTokdummyActdummyRes", "dummy")
			pm := &ProcessorMock{
				rt:      &role.Token{},
				wantErr: nil,
			}
			pdm := &PolicydMock{}
			return test{
				name: "test empty action",
				args: args{
					ctx: context.Background(),
					tok: "dummyTok",
					act: "",
					res: "dummyRes",
				},
				fields: fields{
					policyd:            pdm,
					roleTokenProcessor: pm,
					cache:              c,
					cacheExp:           time.Minute,
				},
				wantErr: "empty action / resource: Access denied due to invalid/empty action/resource values",
			}
		}(),
		func() test {
			c := gache.New()
			c.Set("dummyTokdummyActdummyRes", "dummy")
			pm := &ProcessorMock{
				rt:      &role.Token{},
				wantErr: nil,
			}
			pdm := &PolicydMock{}
			return test{
				name: "test empty res",
				args: args{
					ctx: context.Background(),
					tok: "dummyTok",
					act: "dummyAct",
					res: "",
				},
				fields: fields{
					policyd:            pdm,
					roleTokenProcessor: pm,
					cache:              c,
					cacheExp:           time.Minute,
				},
				wantErr: "empty action / resource: Access denied due to invalid/empty action/resource values",
			}
		}(),
		func() test {
			c := gache.New()
			pm := &ProcessorMock{
				wantErr: errors.New("cannot parse roletoken"),
			}
			pdm := &PolicydMock{}
			return test{
				name: "test parse roletoken error",
				args: args{
					ctx: context.Background(),
					tok: "dummyTok",
					act: "dummyAct",
					res: "dummyRes",
				},
				fields: fields{
					policyd:            pdm,
					roleTokenProcessor: pm,
					cache:              c,
					cacheExp:           time.Minute,
				},
				wantErr: "error verify role token: cannot parse roletoken",
			}
		}(),
		func() test {
			c := gache.New()
			pm := &ProcessorMock{
				rt: &role.Token{},
			}
			pdm := &PolicydMock{
				CheckPolicyFunc: func(context.Context, string, []string, string, string) error {
					return errors.New("deny")
				},
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
					policyd:            pdm,
					roleTokenProcessor: pm,
					cache:              c,
					cacheExp:           time.Minute,
				},
				wantErr: "token unauthorized: deny",
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
			pm := &ProcessorMock{
				rjc:     &role.RoleJWTClaim{},
				wantErr: nil,
			}
			pdm := &PolicydMock{}
			return test{
				name: "test verify success",
				args: args{
					ctx: context.Background(),
					tok: "dummyTok",
					act: "dummyAct",
					res: "dummyRes",
				},
				fields: fields{
					policyd:       pdm,
					roleProcessor: pm,
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
			pm := &ProcessorMock{
				rjc:     &role.RoleJWTClaim{},
				wantErr: nil,
			}
			pdm := &PolicydMock{}
			return test{
				name: "test use cache success",
				args: args{
					ctx: context.Background(),
					tok: "dummyTok",
					act: "dummyAct",
					res: "dummyRes",
				},
				fields: fields{
					policyd:       pdm,
					roleProcessor: pm,
					cache:         c,
					cacheExp:      time.Minute,
				},
				wantErr: "",
			}
		}(),
		func() test {
			c := gache.New()
			c.Set("dummyTokdummyActdummyRes", "dummy")
			pm := &ProcessorMock{
				rjc:     &role.RoleJWTClaim{},
				wantErr: nil,
			}
			pdm := &PolicydMock{}
			return test{
				name: "test empty action",
				args: args{
					ctx: context.Background(),
					tok: "dummyTok",
					act: "",
					res: "dummyRes",
				},
				fields: fields{
					policyd:       pdm,
					roleProcessor: pm,
					cache:         c,
					cacheExp:      time.Minute,
				},
				wantErr: "empty action / resource: Access denied due to invalid/empty action/resource values",
			}
		}(),
		func() test {
			c := gache.New()
			c.Set("dummyTokdummyActdummyRes", "dummy")
			pm := &ProcessorMock{
				rjc:     &role.RoleJWTClaim{},
				wantErr: nil,
			}
			pdm := &PolicydMock{}
			return test{
				name: "test empty res",
				args: args{
					ctx: context.Background(),
					tok: "dummyTok",
					act: "dummyAct",
					res: "",
				},
				fields: fields{
					policyd:       pdm,
					roleProcessor: pm,
					cache:         c,
					cacheExp:      time.Minute,
				},
				wantErr: "empty action / resource: Access denied due to invalid/empty action/resource values",
			}
		}(),
		func() test {
			c := gache.New()
			pm := &ProcessorMock{
				wantErr: errors.New("cannot parse role jwt"),
			}
			pdm := &PolicydMock{}
			return test{
				name: "test parse role jwt error",
				args: args{
					ctx: context.Background(),
					tok: "dummyTok",
					act: "dummyAct",
					res: "dummyRes",
				},
				fields: fields{
					policyd:       pdm,
					roleProcessor: pm,
					cache:         c,
					cacheExp:      time.Minute,
				},
				wantErr: "error verify role jwt: cannot parse role jwt",
			}
		}(),
		func() test {
			c := gache.New()
			pm := &ProcessorMock{
				rjc: &role.RoleJWTClaim{},
			}
			pdm := &PolicydMock{
				CheckPolicyFunc: func(context.Context, string, []string, string, string) error {
					return errors.New("deny")
				},
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
					policyd:       pdm,
					roleProcessor: pm,
					cache:         c,
					cacheExp:      time.Minute,
				},
				wantErr: "token unauthorized: deny",
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
	}
	type args struct {
		ctx       context.Context
		peerCerts []*x509.Certificate
		act       string
		res       string
	}
	type test struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}
	tests := []test{
		func() test {
			crt := `-----BEGIN CERTIFICATE-----
MIICGTCCAcOgAwIBAgIJALLML3PdJAZ1MA0GCSqGSIb3DQEBCwUAMFwxCzAJBgNV
BAYTAlVTMQswCQYDVQQIEwJDQTEPMA0GA1UEChMGQXRoZW56MRcwFQYDVQQLEw5U
ZXN0aW5nIERvbWFpbjEWMBQGA1UEAxMNYXRoZW56LnN5bmNlcjAeFw0xOTA0Mjcw
MjQ2MjNaFw0yOTA0MjQwMjQ2MjNaMFwxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJD
QTEPMA0GA1UEChMGQXRoZW56MRcwFQYDVQQLEw5UZXN0aW5nIERvbWFpbjEWMBQG
A1UEAxMNYXRoZW56LnN5bmNlcjBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQCvv27a
SNAnK0vcN8fqqQgMHwb0EhfVWMwoRTBQFrCmA9mH/84QgI/0kR3ZI+DlDNBCgDHd
rEJZVPyX2V41VOX3AgMBAAGjaDBmMGQGA1UdEQRdMFuGGXNwaWZmZTovL2F0aGVu
ei9zYS9zeW5jZXKGHmF0aGVuejovL3JvbGUvY29yZXRlY2gvcmVhZGVyc4YeYXRo
ZW56Oi8vcm9sZS9jb3JldGVjaC93cml0ZXJzMA0GCSqGSIb3DQEBCwUAA0EAa3Ra
Wo7tEDFBGqSVYSVuoh0GpsWC0VBAYYi9vhAGfp+g5M2oszvRuxOHYsQmYAjYroTJ
bu80CwTnWhmdBo36Ig==
-----END CERTIFICATE-----`
			block, _ := pem.Decode([]byte(crt))
			cert, _ := x509.ParseCertificate(block.Bytes)

			pm := &PolicydMock{
				CheckPolicyFunc: func(ctx context.Context, domain string, roles []string, act, res string) error {
					containRole := func(r string) bool {
						for _, role := range roles {
							if role == r {
								return true
							}
						}
						return false
					}
					if domain != "coretech" {
						return errors.Errorf("invalid domain, got: %s, want: %s", domain, "coretech")
					}
					if !containRole("readers") || !containRole("writers") {
						return errors.Errorf("invalid role, got: %s", roles)
					}
					return nil
				},
			}

			return test{
				name: "parse and verify role cert success",
				fields: fields{
					roleCertURIPrefix: "athenz://role/",
					policyd:           pm,
				},
				args: args{
					ctx: context.Background(),
					peerCerts: []*x509.Certificate{
						cert,
					},
					act: "abc",
					res: "def",
				},
			}
		}(),
		func() test {
			crt := `
-----BEGIN CERTIFICATE-----
MIICLjCCAZegAwIBAgIBADANBgkqhkiG9w0BAQ0FADA0MQswCQYDVQQGEwJ1czEL
MAkGA1UECAwCSEsxCzAJBgNVBAoMAkhLMQswCQYDVQQDDAJISzAeFw0xOTA3MDQw
NjU2MTJaFw0yMDA3MDMwNjU2MTJaMDQxCzAJBgNVBAYTAnVzMQswCQYDVQQIDAJI
SzELMAkGA1UECgwCSEsxCzAJBgNVBAMMAkhLMIGfMA0GCSqGSIb3DQEBAQUAA4GN
ADCBiQKBgQDdUHpdYo/UeYvzB4Z3WvUe2yHsuxrhh7x/D2A5OPb19+ZZy4cdMDUW
qd3hw/tvBWxSUYueL75AifVAQdncUJ+7of3WByFYVSemDrdlD9K/+PyGFZotA+Xj
GmNWjAsGBYuU5roxJZI2c78vJzKj2DU1a9hq/PJ9WGvX4i1Xwf0FKwIDAQABo1Aw
TjAdBgNVHQ4EFgQUiLEo7+nigzdGft2ZEbpkZFxgU+MwHwYDVR0jBBgwFoAUiLEo
7+nigzdGft2ZEbpkZFxgU+MwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOB
gQCiedWe2DXuE0ak1oGV+28qLpyc/Ff9RNNwUbCKB6L/+OWoROVdaz/DoZjfE9vr
ilcIAqkugYyMzW4cY2RexOLYrkyyjLjMj5C2ff4m13gqRLHU0rFpaKpjYr8KYiGD
KSdPh6TRd/kYpv7t6cVm1Orll4O5jh+IdoguGkOCxheMaQ==
-----END CERTIFICATE-----`
			block, _ := pem.Decode([]byte(crt))
			cert, _ := x509.ParseCertificate(block.Bytes)

			pm := &PolicydMock{
				CheckPolicyFunc: func(ctx context.Context, domain string, roles []string, act, res string) error {
					return nil
				},
			}

			return test{
				name: "invalid athenz role certificate, invalid SAN",
				fields: fields{
					roleCertURIPrefix: "athenz://role/",
					policyd:           pm,
				},
				args: args{
					ctx: context.Background(),
					peerCerts: []*x509.Certificate{
						cert,
					},
					act: "abc",
					res: "def",
				},
				wantErr: true,
			}
		}(),
		func() test {
			crt := `-----BEGIN CERTIFICATE-----
MIICGTCCAcOgAwIBAgIJALLML3PdJAZ1MA0GCSqGSIb3DQEBCwUAMFwxCzAJBgNV
BAYTAlVTMQswCQYDVQQIEwJDQTEPMA0GA1UEChMGQXRoZW56MRcwFQYDVQQLEw5U
ZXN0aW5nIERvbWFpbjEWMBQGA1UEAxMNYXRoZW56LnN5bmNlcjAeFw0xOTA0Mjcw
MjQ2MjNaFw0yOTA0MjQwMjQ2MjNaMFwxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJD
QTEPMA0GA1UEChMGQXRoZW56MRcwFQYDVQQLEw5UZXN0aW5nIERvbWFpbjEWMBQG
A1UEAxMNYXRoZW56LnN5bmNlcjBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQCvv27a
SNAnK0vcN8fqqQgMHwb0EhfVWMwoRTBQFrCmA9mH/84QgI/0kR3ZI+DlDNBCgDHd
rEJZVPyX2V41VOX3AgMBAAGjaDBmMGQGA1UdEQRdMFuGGXNwaWZmZTovL2F0aGVu
ei9zYS9zeW5jZXKGHmF0aGVuejovL3JvbGUvY29yZXRlY2gvcmVhZGVyc4YeYXRo
ZW56Oi8vcm9sZS9jb3JldGVjaC93cml0ZXJzMA0GCSqGSIb3DQEBCwUAA0EAa3Ra
Wo7tEDFBGqSVYSVuoh0GpsWC0VBAYYi9vhAGfp+g5M2oszvRuxOHYsQmYAjYroTJ
bu80CwTnWhmdBo36Ig==
-----END CERTIFICATE-----`
			block, _ := pem.Decode([]byte(crt))
			cert, _ := x509.ParseCertificate(block.Bytes)

			pm := &PolicydMock{
				CheckPolicyFunc: func(ctx context.Context, domain string, roles []string, act, res string) error {
					return errors.New("dummy")
				},
			}

			return test{
				name: "invalid athenz role certificate, deny by policyd",
				fields: fields{
					roleCertURIPrefix: "athenz://role/",
					policyd:           pm,
				},
				args: args{
					ctx: context.Background(),
					peerCerts: []*x509.Certificate{
						cert,
					},
					act: "abc",
					res: "def",
				},
				wantErr: true,
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
			}
			if got := a.GetPolicyCache(tt.args.ctx); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("authorizer.GetPolicyCache() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_authorizer_Verify(t *testing.T) {
	type fields struct {
		verifiers []verifier
	}
	type args struct {
		r   *http.Request
		act string
		res string
	}
	type test struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}
	tests := []test{
		{
			name: "Verify success, 1 verifier",
			fields: fields{
				verifiers: []verifier{
					func(r *http.Request, act, res string) error {
						return nil
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Verify success, multiple verifier",
			fields: fields{
				verifiers: []verifier{
					func(r *http.Request, act, res string) error {
						return errors.Errorf("Testing verify error 1")
					},
					func(r *http.Request, act, res string) error {
						return nil
					},
					func(r *http.Request, act, res string) error {
						return nil
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Verify fail, 1 verifier",
			fields: fields{
				verifiers: []verifier{
					func(r *http.Request, act, res string) error {
						return errors.Errorf("Testing verify error 1")
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Verify fail, multiple verifier",
			fields: fields{
				verifiers: []verifier{
					func(r *http.Request, act, res string) error {
						return errors.Errorf("Testing verify error 1")
					},
					func(r *http.Request, act, res string) error {
						return errors.Errorf("Testing verify error 2")
					},
					func(r *http.Request, act, res string) error {
						return errors.Errorf("Testing verify error 3")
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &authorizer{
				verifiers: tt.fields.verifiers,
			}
			if err := a.Verify(tt.args.r, tt.args.act, tt.args.res); (err != nil) != tt.wantErr {
				t.Errorf("authorizer.Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
func Test_authorizer_VerifyAccessToken(t *testing.T) {
	type fields struct {
		policyd       policy.Daemon
		roleProcessor role.Processor
		cache         gache.Gache
		cacheExp      time.Duration
	}
	type args struct {
		ctx  context.Context
		tok  string
		act  string
		res  string
		cert *x509.Certificate
	}
	type test struct {
		name      string
		fields    fields
		args      args
		wantErr   string
		checkFunc func(prov *authorizer) error
	}
	tests := []test{
		func() test {
			now := fastime.Now()
			c := gache.New()
			pm := &ProcessorMock{
				act: &role.OAuth2AccessTokenClaim{
					Scope: []string{"role"},
					BaseClaim: role.BaseClaim{
						StandardClaims: jwtgo.StandardClaims{
							Audience: "domain",
						},
					},
				},
				wantErr: nil,
			}
			pdm := &PolicydMock{
				CheckPolicyFunc: func(ctx context.Context, domain string, roles []string, action, resource string) error {
					if domain != "domain" || len(roles) != 1 || roles[0] != "role" {
						return errors.New("Audience/Scope mismatch")
					}
					return nil
				},
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
					policyd:       pdm,
					roleProcessor: pm,
					cache:         c,
					cacheExp:      time.Minute,
				},
				wantErr: "",
				checkFunc: func(prov *authorizer) error {
					_, expiry, ok := prov.cache.GetWithExpire("dummyTokdummyActdummyRes")
					if !ok {
						return errors.New("cannot get dummyTokdummyActdummyRes from cache")
					}
					wantExpiry := now.Add(time.Minute).UnixNano()
					if wantExpiry > expiry {
						return fmt.Errorf("cache expiry: got = %v, want: %v", expiry, wantExpiry)
					}
					return nil
				},
			}
		}(),
		func() test {
			now := fastime.Now()
			c := gache.New()
			c.SetWithExpire("dummyTokdummyActdummyRes", "dummy", time.Minute)
			pm := &ProcessorMock{
				act:     &role.OAuth2AccessTokenClaim{},
				wantErr: nil,
			}
			pdm := &PolicydMock{
				CheckPolicyFunc: func(ctx context.Context, domain string, roles []string, action, resource string) error {
					if domain != "domain" || len(roles) != 1 || roles[0] != "role" {
						return errors.New("Audience/Scope mismatch")
					}
					return nil
				},
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
					policyd:       pdm,
					roleProcessor: pm,
					cache:         c,
					cacheExp:      time.Minute,
				},
				wantErr: "",
				checkFunc: func(prov *authorizer) error {
					_, expiry, ok := prov.cache.GetWithExpire("dummyTokdummyActdummyRes")
					if !ok {
						return errors.New("cannot get dummyTokdummyActdummyRes from cache")
					}
					wantExpiry := now.Add(time.Minute).UnixNano()
					if wantExpiry > expiry {
						return fmt.Errorf("cache expiry: got = %v, want: %v", expiry, wantExpiry)
					}
					return nil
				},
			}
		}(),
		func() test {
			c := gache.New()
			c.Set("dummyTokdummyActdummyRes", "dummy")
			pm := &ProcessorMock{
				act:     &role.OAuth2AccessTokenClaim{},
				wantErr: nil,
			}
			pdm := &PolicydMock{}
			return test{
				name: "test empty action",
				args: args{
					ctx: context.Background(),
					tok: "dummyTok",
					act: "",
					res: "dummyRes",
				},
				fields: fields{
					policyd:       pdm,
					roleProcessor: pm,
					cache:         c,
					cacheExp:      time.Minute,
				},
				wantErr: "empty action / resource: Access denied due to invalid/empty action/resource values",
			}
		}(),
		func() test {
			c := gache.New()
			c.Set("dummyTokdummyActdummyRes", "dummy")
			pm := &ProcessorMock{
				act:     &role.OAuth2AccessTokenClaim{},
				wantErr: nil,
			}
			pdm := &PolicydMock{}
			return test{
				name: "test empty res",
				args: args{
					ctx: context.Background(),
					tok: "dummyTok",
					act: "dummyAct",
					res: "",
				},
				fields: fields{
					policyd:       pdm,
					roleProcessor: pm,
					cache:         c,
					cacheExp:      time.Minute,
				},
				wantErr: "empty action / resource: Access denied due to invalid/empty action/resource values",
			}
		}(),
		func() test {
			c := gache.New()
			pm := &ProcessorMock{
				wantErr: errors.New("cannot parse access token"),
			}
			pdm := &PolicydMock{}
			return test{
				name: "test parse access token error",
				args: args{
					ctx: context.Background(),
					tok: "dummyTok",
					act: "dummyAct",
					res: "dummyRes",
				},
				fields: fields{
					policyd:       pdm,
					roleProcessor: pm,
					cache:         c,
					cacheExp:      time.Minute,
				},
				wantErr: "error verify access token: cannot parse access token",
			}
		}(),
		func() test {
			c := gache.New()
			pm := &ProcessorMock{
				act: &role.OAuth2AccessTokenClaim{},
			}
			pdm := &PolicydMock{
				CheckPolicyFunc: func(context.Context, string, []string, string, string) error {
					return errors.New("deny")
				},
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
					policyd:       pdm,
					roleProcessor: pm,
					cache:         c,
					cacheExp:      time.Minute,
				},
				wantErr: "token unauthorized: deny",
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &authorizer{
				policyd:       tt.fields.policyd,
				roleProcessor: tt.fields.roleProcessor,
				cache:         tt.fields.cache,
				cacheExp:      tt.fields.cacheExp,
			}
			err := a.VerifyAccessToken(tt.args.ctx, tt.args.tok, tt.args.act, tt.args.res, tt.args.cert)
			if err != nil {
				if err.Error() != tt.wantErr {
					t.Errorf("authorizer.VerifyAccessToken() error want:%s, result: %s", tt.wantErr, err.Error())
					return
				}
			} else {
				if tt.wantErr != "" {
					t.Errorf("authorizer.VerifyAccessToken() return nil.  want %s", tt.wantErr)
					return
				}
			}
			if tt.checkFunc != nil {
				if err := tt.checkFunc(a); err != nil {
					t.Errorf("authorizer.VerifyAccessToken() error: %v", err)
				}
			}
		})
	}
}
