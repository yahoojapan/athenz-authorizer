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
	"context"
	"testing"
	"time"

	"github.com/kpango/gache"
	"github.com/pkg/errors"
	"github.com/yahoojapan/athenz-policy-updater/config"
	"github.com/yahoojapan/athenz-policy-updater/policy"
	"github.com/yahoojapan/athenz-policy-updater/role"
)

func TestNew(t *testing.T) {
	type args struct {
		opts []Option
	}
	tests := []struct {
		name      string
		args      args
		checkFunc func(Providerd, error) error
	}{
		{
			name: "test new success",
			args: args{
				[]Option{},
			},
			checkFunc: func(prov Providerd, err error) error {
				if err != nil {
					return errors.Wrap(err, "unexpected error")
				}
				if prov.(*provider).athenzURL != "www.athenz.com/zts/v1" {
					return errors.New("invalid url")
				}
				if prov.(*provider).athenzConfd == nil {
					return errors.New("cannot new athenzConfd")
				}
				if prov.(*provider).policyd == nil {
					return errors.New("cannot new policyd")
				}
				return nil
			},
		},
		{
			name: "test new success with options",
			args: args{
				[]Option{AthenzURL("www.dummy.com")},
			},
			checkFunc: func(prov Providerd, err error) error {
				if err != nil {
					return errors.Wrap(err, "unexpected error")
				}
				if prov.(*provider).athenzURL != "www.dummy.com" {
					return errors.New("invalid url")
				}
				return nil
			},
		},
		{
			name: "test NewAthenzConfd returns error",
			args: args{
				[]Option{AthenzConfEtagExpTime("dummy")},
			},
			checkFunc: func(prov Providerd, err error) error {
				if err.Error() != "error create athenzConfd: invalid etag expire time: time: invalid duration dummy" {
					return errors.Wrap(err, "unexpected error")
				}
				return nil
			},
		},
		{
			name: "test NewAthenzConfd returns error",
			args: args{
				[]Option{PolicyEtagExpTime("dummy")},
			},
			checkFunc: func(prov Providerd, err error) error {
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

func TestStartProviderd(t *testing.T) {
	type fields struct {
		athenzConfd config.AthenzConfd
		policyd     policy.Policyd
		cache       gache.Gache
		cacheExp    time.Duration
	}
	type args struct {
		ctx context.Context
	}
	type test struct {
		name      string
		fields    fields
		args      args
		checkFunc func(Providerd, error) error
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
			return test{
				name: "test context done",
				fields: fields{
					athenzConfd: cm,
					policyd:     pm,
					cache:       gache.New(),
					cacheExp:    time.Minute,
				},
				args: args{
					ctx: ctx,
				},
				checkFunc: func(prov Providerd, err error) error {
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
			return test{
				name: "test context done",
				fields: fields{
					athenzConfd: cm,
					policyd:     pm,
					cache:       gache.New(),
					cacheExp:    time.Minute,
				},
				args: args{
					ctx: ctx,
				},
				checkFunc: func(prov Providerd, err error) error {
					if err.Error() != "update athenz conf error: confd error" {
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
			return test{
				name: "test context done",
				fields: fields{
					athenzConfd: cm,
					policyd:     pm,
					cache:       gache.New(),
					cacheExp:    time.Minute,
				},
				args: args{
					ctx: ctx,
				},
				checkFunc: func(prov Providerd, err error) error {
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
			prov := &provider{
				athenzConfd: tt.fields.athenzConfd,
				policyd:     tt.fields.policyd,
				cache:       tt.fields.cache,
				cacheExp:    tt.fields.cacheExp,
			}
			ch := prov.StartProviderd(tt.args.ctx)
			goter := <-ch
			if err := tt.checkFunc(prov, goter); err != nil {
				t.Errorf("StartProviderd() error = %v", err)
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
		policyd         policy.Policyd
		cache           gache.Gache
		cacheExp        time.Duration
		roleTokenParser role.RoleTokenParser
	}
	type test struct {
		name      string
		args      args
		fields    fields
		wantErr   string
		checkFunc func(*provider) error
	}
	tests := []test{
		func() test {
			c := gache.New()
			rm := &RoleTokenMock{
				rt:      &role.RoleToken{},
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
					policyd:         cm,
					roleTokenParser: rm,
					cache:           c,
					cacheExp:        time.Minute,
				},
				wantErr: "",
				checkFunc: func(prov *provider) error {
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
			rm := &RoleTokenMock{
				rt:      &role.RoleToken{},
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
					policyd:         cm,
					roleTokenParser: rm,
					cache:           c,
					cacheExp:        time.Minute,
				},
				wantErr: "",
			}
		}(),
		func() test {
			c := gache.New()
			c.Set("dummyTokdummyActdummyRes", "dummy")
			rm := &RoleTokenMock{
				rt:      &role.RoleToken{},
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
					policyd:         cm,
					roleTokenParser: rm,
					cache:           c,
					cacheExp:        time.Minute,
				},
				wantErr: "empty action / resource: Access denied due to invalid/empty action/resource values",
			}
		}(),
		func() test {
			c := gache.New()
			c.Set("dummyTokdummyActdummyRes", "dummy")
			rm := &RoleTokenMock{
				rt:      &role.RoleToken{},
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
					policyd:         cm,
					roleTokenParser: rm,
					cache:           c,
					cacheExp:        time.Minute,
				},
				wantErr: "empty action / resource: Access denied due to invalid/empty action/resource values",
			}
		}(),
		func() test {
			c := gache.New()
			rm := &RoleTokenMock{
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
					policyd:         cm,
					roleTokenParser: rm,
					cache:           c,
					cacheExp:        time.Minute,
				},
				wantErr: "error verify role token: cannot parse roletoken",
			}
		}(),
		func() test {
			c := gache.New()
			rm := &RoleTokenMock{
				rt: &role.RoleToken{},
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
					policyd:         cm,
					roleTokenParser: rm,
					cache:           c,
					cacheExp:        time.Minute,
				},
				wantErr: "role token unauthorizate: deny",
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prov := &provider{
				policyd:         tt.fields.policyd,
				roleTokenParser: tt.fields.roleTokenParser,
				cache:           tt.fields.cache,
				cacheExp:        tt.fields.cacheExp,
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
