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
		pubkeyd  pubkey.Pubkeyd
		policyd  policy.Policyd
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
		policyd            policy.Policyd
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
				wantErr: "role token unauthorizate: deny",
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
