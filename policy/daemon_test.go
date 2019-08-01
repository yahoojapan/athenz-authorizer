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
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ardielle/ardielle-go/rdl"
	cmp "github.com/google/go-cmp/cmp"
	"github.com/kpango/gache"
	"github.com/pkg/errors"
	authcore "github.com/yahoo/athenz/libs/go/zmssvctoken"
	"github.com/yahoo/athenz/utils/zpe-updater/util"
	"github.com/yahoojapan/athenz-authorizer/pubkey"
)

func TestNew(t *testing.T) {
	type args struct {
		opts []Option
	}
	tests := []struct {
		name      string
		args      args
		want      Daemon
		checkFunc func(got Daemon) error
		wantErr   bool
	}{
		{
			name: "new success",
			args: args{
				opts: []Option{},
			},
			checkFunc: func(got Daemon) error {
				p := got.(*policyd)
				if p.expireMargin != time.Hour*3 {
					return errors.New("invalid expireMargin")
				}
				return nil
			},
		},
		{
			name: "new success with options",
			args: args{
				opts: []Option{WithExpireMargin("5s")},
			},
			checkFunc: func(got Daemon) error {
				p := got.(*policyd)
				if p.expireMargin != time.Second*5 {
					return errors.New("invalid expireMargin")
				}
				return nil
			},
		},
		{
			name: "new error due to options",
			args: args{
				opts: []Option{WithEtagExpTime("dummy")},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.args.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.checkFunc != nil {
				if err := tt.checkFunc(got); err != nil {
					t.Errorf("New() = %v", err)
				}
			}
		})
	}
}

func Test_policyd_Start(t *testing.T) {
	type fields struct {
		expireMargin          time.Duration
		rolePolicies          gache.Gache
		policyExpiredDuration time.Duration
		refreshDuration       time.Duration
		errRetryInterval      time.Duration
		pkp                   pubkey.Provider
		etagCache             gache.Gache
		etagFlushDur          time.Duration
		etagExpTime           time.Duration
		athenzURL             string
		athenzDomains         []string
		client                *http.Client
	}
	type args struct {
		ctx context.Context
	}
	type test struct {
		name      string
		fields    fields
		args      args
		checkFunc func(*policyd, <-chan error) error
		afterFunc func()
	}
	tests := []test{
		func() test {
			handler := http.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Add("ETag", "dummyEtag")
				w.Write([]byte(`{"signedPolicyData":{"policyData":{"domain":"dummyDom","policies":[{"name":"dummyDom:policy.dummyPol","modified":"2099-02-14T05:42:07.219Z","assertions":[{"role":"dummyDom:role.dummyRole","resource":"dummyDom:dummyRes","action":"dummyAct","effect":"ALLOW"}]}]},"zmsSignature":"dummySig","zmsKeyId":"dummyKeyID","modified":"2099-03-04T04:33:27.318Z","expires":"2099-03-12T08:11:18.729Z"},"signature":"dummySig","keyId":"dummyKeyID"}`))
				w.WriteHeader(http.StatusOK)
			}))
			srv := httptest.NewTLSServer(handler)
			ctx, cancel := context.WithCancel(context.Background())

			return test{
				name: "Start success",
				fields: fields{
					rolePolicies:          gache.New(),
					policyExpiredDuration: time.Minute * 30,
					athenzURL:             strings.Replace(srv.URL, "https://", "", 1),
					etagCache:             gache.New(),
					etagExpTime:           time.Minute,
					etagFlushDur:          time.Second,
					refreshDuration:       time.Second,
					expireMargin:          time.Hour,
					client:                srv.Client(),
					pkp: func(e pubkey.AthenzEnv, id string) authcore.Verifier {
						return VerifierMock{
							VerifyFunc: func(d, s string) error {
								return nil
							},
						}
					},
					athenzDomains: []string{"dummyDom"},
				},
				args: args{
					ctx: ctx,
				},
				checkFunc: func(p *policyd, ch <-chan error) error {
					time.Sleep(time.Millisecond * 100)
					cancel()
					asss, ok := p.rolePolicies.Get("dummyDom:role.dummyRole")
					if !ok {
						return errors.New("rolePolicies is empty")
					}
					if len(asss.([]*Assertion)) != 1 {
						return errors.Errorf("invalid length assertions. want: 1, result: %d", len(asss.([]*Assertion)))
					}
					_, ok = p.etagCache.Get("dummyDom")
					if !ok {
						return errors.New("etagCache is empty")
					}
					return nil
				},
				afterFunc: func() {
					cancel()
				},
			}
		}(),
		func() test {
			c := 0
			handler := http.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c++
				w.Header().Add("ETag", fmt.Sprintf("%v%d", "dummyEtag", c))
				res := fmt.Sprintf("dummyRes%d", c)
				act := fmt.Sprintf("dummyAct%d", c)
				w.Write([]byte(fmt.Sprintf(`{"signedPolicyData":{"policyData":{"domain":"dummyDom","policies":[{"name":"dummyDom:policy.dummyPol","modified":"2099-02-14T05:42:07.219Z","assertions":[{"role":"dummyDom:role.dummyRole","resource":"dummyDom:%s","action":"%s","effect":"ALLOW"}]}]},"zmsSignature":"dummySig","zmsKeyId":"dummyKeyID","modified":"2099-03-04T04:33:27.318Z","expires":"2099-03-12T08:11:18.729Z"},"signature":"dummySig","keyId":"dummyKeyID"}`, res, act)))
				w.WriteHeader(http.StatusOK)
			}))
			srv := httptest.NewTLSServer(handler)
			ctx, cancel := context.WithCancel(context.Background())

			return test{
				name: "Start can update cache",
				fields: fields{
					rolePolicies:          gache.New(),
					policyExpiredDuration: time.Minute * 30,
					athenzURL:             strings.Replace(srv.URL, "https://", "", 1),
					etagCache:             gache.New(),
					etagExpTime:           time.Minute,
					etagFlushDur:          time.Second,
					refreshDuration:       time.Millisecond * 30,
					expireMargin:          time.Hour,
					client:                srv.Client(),
					pkp: func(e pubkey.AthenzEnv, id string) authcore.Verifier {
						return VerifierMock{
							VerifyFunc: func(d, s string) error {
								return nil
							},
						}
					},
					athenzDomains: []string{"dummyDom"},
				},
				args: args{
					ctx: ctx,
				},
				checkFunc: func(p *policyd, ch <-chan error) error {
					time.Sleep(time.Millisecond * 100)
					cancel()
					time.Sleep(time.Millisecond * 50)
					asss, ok := p.rolePolicies.Get("dummyDom:role.dummyRole")
					if !ok {
						return errors.New("rolePolicies is empty")
					}

					if len(asss.([]*Assertion)) != 1 {
						return errors.Errorf("invalid length assertions. want: 1, result: %d", len(asss.([]*Assertion)))
					}
					ass := asss.([]*Assertion)[0]
					if ass.Reg.String() == "^dummyact1-dummyres1$" {
						return errors.Errorf("invalid assertion, got: %v, want: ^dummyact%d-dummyres%d$", ass.Reg.String(), c, c)
					}

					ec, ok := p.etagCache.Get("dummyDom")
					if !ok {
						return errors.New("etagCache is empty")
					}
					ecwant := fmt.Sprintf("dummyEtag%d", c)
					if ec.(*etagCache).eTag != ecwant {
						return errors.Errorf("invalid etag, got: %v, want: %s", ec, ecwant)
					}

					return nil
				},
				afterFunc: func() {
					cancel()
				},
			}
		}(),
		func() test {
			c := 0
			handler := http.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if c < 3 {
					c++
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.Header().Add("ETag", fmt.Sprintf("%v%d", "dummyEtag", c))
				res := fmt.Sprintf("dummyRes%d", c)
				act := fmt.Sprintf("dummyAct%d", c)
				w.Write([]byte(fmt.Sprintf(`{"signedPolicyData":{"policyData":{"domain":"dummyDom","policies":[{"name":"dummyDom:policy.dummyPol","modified":"2099-02-14T05:42:07.219Z","assertions":[{"role":"dummyDom:role.dummyRole","resource":"dummyDom:%s","action":"%s","effect":"ALLOW"}]}]},"zmsSignature":"dummySig","zmsKeyId":"dummyKeyID","modified":"2099-03-04T04:33:27.318Z","expires":"2099-03-12T08:11:18.729Z"},"signature":"dummySig","keyId":"dummyKeyID"}`, res, act)))
				w.WriteHeader(http.StatusOK)
			}))
			srv := httptest.NewTLSServer(handler)
			ctx, cancel := context.WithCancel(context.Background())

			return test{
				name: "Start retry update",
				fields: fields{
					rolePolicies:          gache.New(),
					policyExpiredDuration: time.Minute * 30,
					athenzURL:             strings.Replace(srv.URL, "https://", "", 1),
					etagCache:             gache.New(),
					etagExpTime:           time.Minute,
					etagFlushDur:          time.Second,
					refreshDuration:       time.Minute,
					errRetryInterval:      time.Millisecond * 5,
					expireMargin:          time.Hour,
					client:                srv.Client(),
					pkp: func(e pubkey.AthenzEnv, id string) authcore.Verifier {
						return VerifierMock{
							VerifyFunc: func(d, s string) error {
								return nil
							},
						}
					},
					athenzDomains: []string{"dummyDom"},
				},
				args: args{
					ctx: ctx,
				},
				checkFunc: func(p *policyd, ch <-chan error) error {
					time.Sleep(time.Millisecond * 100)
					cancel()
					time.Sleep(time.Millisecond * 50)
					asss, ok := p.rolePolicies.Get("dummyDom:role.dummyRole")
					if !ok {
						return errors.New("rolePolicies is empty")
					}

					if len(asss.([]*Assertion)) != 1 {
						return errors.Errorf("invalid length assertions. want: 1, result: %d", len(asss.([]*Assertion)))
					}
					ass := asss.([]*Assertion)[0]
					if ass.Reg.String() != fmt.Sprintf("^dummyact%d-dummyres%d$", c, c) {
						return errors.Errorf("invalid assertion, got: %v, want: ^dummyact%d-dummyres%d$", ass.Reg.String(), c, c)
					}

					ec, ok := p.etagCache.Get("dummyDom")
					if !ok {
						return errors.New("etagCache is empty")
					}
					ecwant := fmt.Sprintf("dummyEtag%d", c)
					if ec.(*etagCache).eTag != ecwant {
						return errors.Errorf("invalid etag, got: %v, want: %s", ec, ecwant)
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
			if tt.afterFunc != nil {
				defer tt.afterFunc()
			}
			p := &policyd{
				expireMargin:          tt.fields.expireMargin,
				rolePolicies:          tt.fields.rolePolicies,
				policyExpiredDuration: tt.fields.policyExpiredDuration,
				refreshDuration:       tt.fields.refreshDuration,
				errRetryInterval:      tt.fields.errRetryInterval,
				pkp:                   tt.fields.pkp,
				etagCache:             tt.fields.etagCache,
				etagFlushDur:          tt.fields.etagFlushDur,
				etagExpTime:           tt.fields.etagExpTime,
				athenzURL:             tt.fields.athenzURL,
				athenzDomains:         tt.fields.athenzDomains,
				client:                tt.fields.client,
			}
			ch := p.Start(tt.args.ctx)
			if tt.checkFunc != nil {
				if err := tt.checkFunc(p, ch); err != nil {
					t.Errorf("policy.Start() error = %v", err)
				}
			}
		})
	}
}

func Test_policyd_Update(t *testing.T) {
	type fields struct {
		expireMargin          time.Duration
		rolePolicies          gache.Gache
		policyExpiredDuration time.Duration
		refreshDuration       time.Duration
		errRetryInterval      time.Duration
		pkp                   pubkey.Provider
		etagCache             gache.Gache
		etagFlushDur          time.Duration
		etagExpTime           time.Duration
		athenzURL             string
		athenzDomains         []string
		client                *http.Client
	}
	type args struct {
		ctx context.Context
	}
	type test struct {
		name       string
		fields     fields
		args       args
		beforeFunc func()
		checkFunc  func(pol *policyd) error
		wantErr    string
		afterFunc  func()
	}
	tests := []test{
		func() test {
			handler := http.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Add("ETag", "dummyEtag")
				w.Write([]byte(`{"signedPolicyData":{"policyData":{"domain":"dummyDom","policies":[{"name":"dummyDom:policy.dummyPol","modified":"2099-02-14T05:42:07.219Z","assertions":[{"role":"dummyDom:role.dummyRole","resource":"dummyDom:dummyRes","action":"dummyAct","effect":"ALLOW"}]}]},"zmsSignature":"dummySig","zmsKeyId":"dummyKeyID","modified":"2099-03-04T04:33:27.318Z","expires":"2099-03-12T08:11:18.729Z"},"signature":"dummySig","keyId":"dummyKeyID"}`))
				w.WriteHeader(http.StatusOK)
			}))
			srv := httptest.NewTLSServer(handler)

			return test{
				name: "Update policy success",
				fields: fields{
					rolePolicies:          gache.New(),
					policyExpiredDuration: time.Minute * 30,
					athenzURL:             strings.Replace(srv.URL, "https://", "", 1),
					etagCache:             gache.New(),
					etagExpTime:           time.Minute,
					expireMargin:          time.Hour,
					client:                srv.Client(),
					pkp: func(e pubkey.AthenzEnv, id string) authcore.Verifier {
						return VerifierMock{
							VerifyFunc: func(d, s string) error {
								return nil
							},
						}
					},
					athenzDomains: []string{"dummyDom"},
				},
				args: args{
					ctx: context.Background(),
				},
				wantErr: "",
				checkFunc: func(pol *policyd) error {
					pols, ok := pol.rolePolicies.Get("dummyDom:role.dummyRole")
					if !ok {
						return errors.New("role policies not found")
					}
					if len(pols.([]*Assertion)) != 1 {
						return errors.New("role policies not correct")
					}

					return nil
				},
			}
		}(),
		func() test {
			handler := http.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				domain := strings.Split(r.URL.Path, "/")[2]

				w.Header().Add("ETag", domain+"Etag")
				spd := fmt.Sprintf(`{"signedPolicyData":{"policyData":{"domain":"%s","policies":[{"name":"%s:policy.dummyPol","modified":"2099-02-14T05:42:07.219Z","assertions":[{"role":"%s:role.dummyRole","resource":"%s:dummyRes","action":"dummyAct","effect":"ALLOW"}]}]},"zmsSignature":"dummySig","zmsKeyId":"dummyKeyID","modified":"2099-03-04T04:33:27.318Z","expires":"2099-03-12T08:11:18.729Z"},"signature":"dummySig","keyId":"dummyKeyID"}`, domain, domain, domain, domain)
				w.Write([]byte(spd))
				w.WriteHeader(http.StatusOK)
			}))
			srv := httptest.NewTLSServer(handler)

			domains := make([]string, 1000)
			for i := 0; i < 1000; i++ {
				domains[i] = fmt.Sprintf("dummyDom%d", i)
			}

			return test{
				name: "Update policy success with multiple athenz domains",
				fields: fields{
					rolePolicies:          gache.New(),
					athenzURL:             strings.Replace(srv.URL, "https://", "", 1),
					etagCache:             gache.New(),
					etagExpTime:           time.Minute,
					policyExpiredDuration: time.Second * 120,
					expireMargin:          time.Hour,
					client:                srv.Client(),
					pkp: func(e pubkey.AthenzEnv, id string) authcore.Verifier {
						return VerifierMock{
							VerifyFunc: func(d, s string) error {
								return nil
							},
						}
					},
					athenzDomains: domains,
				},
				args: args{
					ctx: context.Background(),
				},
				checkFunc: func(pol *policyd) error {
					if len(pol.rolePolicies.ToRawMap(context.Background())) != len(domains) {
						return errors.New("role policies length is not correct")
					}

					for _, dom := range domains {
						domRole := fmt.Sprintf("%s:role.dummyRole", dom)
						pols, ok := pol.rolePolicies.Get(domRole)
						if !ok {
							return errors.Errorf("role policies %s not found", domRole)
						}
						if len(pols.([]*Assertion)) != 1 {
							return errors.Errorf("role policies of %s not correct", domRole)
						}
					}

					return nil
				},
			}
		}(),
		func() test {
			handler := http.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Add("ETag", "dummyEtag")
				w.Write([]byte(`{"signedPolicyData":{"policyData":{"domain":"dummyDom","policies":[{"name":"dummyDom:policy.dummyPol","modified":"2099-02-14T05:42:07.219Z","assertions":[{"role":"dummyDom:role.dummyRole","resource":"dummyDom:dummyRes","action":"dummyAct","effect":"ALLOW"}]}]},"zmsSignature":"dummySig","zmsKeyId":"dummyKeyID","modified":"2099-03-04T04:33:27.318Z","expires":"2099-03-12T08:11:18.729Z"},"signature":"dummySig","keyId":"dummyKeyID"}`))
				w.WriteHeader(http.StatusOK)
			}))
			srv := httptest.NewTLSServer(handler)

			ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Millisecond*10))
			return test{
				name: "Update error, context timeout",
				fields: fields{
					rolePolicies:          gache.New(),
					policyExpiredDuration: time.Minute * 30,
					athenzURL:             strings.Replace(srv.URL, "https://", "", 1),
					etagCache:             gache.New(),
					etagExpTime:           time.Minute,
					expireMargin:          time.Hour,
					client:                srv.Client(),
					pkp: func(e pubkey.AthenzEnv, id string) authcore.Verifier {
						return VerifierMock{
							VerifyFunc: func(d, s string) error {
								return nil
							},
						}
					},
					athenzDomains: []string{"dummyDom"},
				},
				args: args{
					ctx: ctx,
				},
				wantErr: "context deadline exceeded",
				beforeFunc: func() {
					time.Sleep(time.Second)
				},
				afterFunc: func() {
					cancel()
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.afterFunc != nil {
				defer tt.afterFunc()
			}

			p := &policyd{
				expireMargin:          tt.fields.expireMargin,
				rolePolicies:          tt.fields.rolePolicies,
				policyExpiredDuration: tt.fields.policyExpiredDuration,
				refreshDuration:       tt.fields.refreshDuration,
				errRetryInterval:      tt.fields.errRetryInterval,
				pkp:                   tt.fields.pkp,
				etagCache:             tt.fields.etagCache,
				etagFlushDur:          tt.fields.etagFlushDur,
				etagExpTime:           tt.fields.etagExpTime,
				athenzURL:             tt.fields.athenzURL,
				athenzDomains:         tt.fields.athenzDomains,
				client:                tt.fields.client,
			}
			if tt.beforeFunc != nil {
				tt.beforeFunc()
			}
			if err := p.Update(tt.args.ctx); (err != nil) && tt.wantErr != "" && err.Error() != tt.wantErr {
				t.Errorf("policy.Update() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.checkFunc != nil {
				if err := tt.checkFunc(p); err != nil {
					t.Errorf("policy.Update() error = %v", err)
				}
			}
		})
	}
}

func Test_policyd_CheckPolicy(t *testing.T) {
	type fields struct {
		expireMargin     time.Duration
		rolePolicies     gache.Gache
		refreshDuration  time.Duration
		errRetryInterval time.Duration
		pkp              pubkey.Provider
		etagCache        gache.Gache
		etagFlushDur     time.Duration
		etagExpTime      time.Duration
		athenzURL        string
		athenzDomains    []string
		client           *http.Client
	}
	type args struct {
		ctx      context.Context
		domain   string
		roles    []string
		action   string
		resource string
	}
	type test struct {
		name   string
		fields fields
		args   args
		want   error
	}
	tests := []test{
		{
			name: "check policy allow success",
			fields: fields{
				rolePolicies: func() gache.Gache {
					g := gache.New()
					g.Set("dummyDom:role.dummyRole", []*Assertion{
						func() *Assertion {
							a, _ := NewAssertion("dummyAct1", "dummyDom1:dummyRes1", "deny")
							return a
						}(),
						func() *Assertion {
							a, _ := NewAssertion("dummyAct2", "dummyDom2:dummyRes2", "deny")
							return a
						}(),
						func() *Assertion {
							a, _ := NewAssertion("dummyAct", "dummyDom:dummyRes", "allow")
							return a
						}(),
					})
					return g
				}(),
			},
			args: args{
				ctx:      context.Background(),
				domain:   "dummyDom",
				roles:    []string{"dummyRole"},
				action:   "dummyAct",
				resource: "dummyRes",
			},
			want: nil,
		},
		{
			name: "check policy deny",
			fields: fields{
				rolePolicies: func() gache.Gache {
					g := gache.New()
					g.Set("dummyDom:role.dummyRole", []*Assertion{
						func() *Assertion {
							a, _ := NewAssertion("dummyAct", "dummyDom:dummyRes", "deny")
							return a
						}(),
					})
					return g
				}(),
			},
			args: args{
				ctx:      context.Background(),
				domain:   "dummyDom",
				roles:    []string{"dummyRole"},
				action:   "dummyAct",
				resource: "dummyRes",
			},
			want: errors.New("policy deny: Access Check was explicitly denied"),
		},
		{
			name: "check policy not found",
			fields: fields{
				rolePolicies: gache.New(),
			},
			args: args{
				ctx:      context.Background(),
				domain:   "dummyDom",
				roles:    []string{"dummyRole"},
				action:   "dummyAct",
				resource: "dummyRes",
			},
			want: errors.New("no match: Access denied due to no match to any of the assertions defined in domain policy file"),
		},
		{
			name: "check policy allow success with multiple roles",
			fields: fields{
				rolePolicies: func() gache.Gache {
					g := gache.New()
					g.Set("dummyDom:role.dummyRole", []*Assertion{
						func() *Assertion {
							a, _ := NewAssertion("dummyAct1", "dummyDom1:dummyRes1", "deny")
							return a
						}(),
						func() *Assertion {
							a, _ := NewAssertion("dummyAct2", "dummyDom2:dummyRes2", "deny")
							return a
						}(),
						func() *Assertion {
							a, _ := NewAssertion("dummyAct", "dummyDom:dummyRes", "allow")
							return a
						}(),
					})
					return g
				}(),
			},
			args: args{
				ctx:      context.Background(),
				domain:   "dummyDom",
				roles:    []string{"dummyRole1", "dummyRole"},
				action:   "dummyAct",
				resource: "dummyRes",
			},
			want: nil,
		},
		{
			name: "check policy no match with assertion resource domain mismatch",
			fields: fields{
				rolePolicies: func() gache.Gache {
					g := gache.New()
					g.Set("dummyDom:role.dummyRole", []*Assertion{
						func() *Assertion {
							a, _ := NewAssertion("dummyAct", "dummyDom3:dummyRes", "allow")
							return a
						}(),
					})
					return g
				}(),
			},
			args: args{
				ctx:      context.Background(),
				domain:   "dummyDom",
				roles:    []string{"dummyRole1", "dummyRole"},
				action:   "dummyAct",
				resource: "dummyRes",
			},
			want: errors.New("no match: Access denied due to no match to any of the assertions defined in domain policy file"),
		},
		/*
			test{
				name: "check policy deny with multiple roles with allow and deny",
				fields: fields{
					rolePolicies: func() gache.Gache {
						g := gache.New()
						for i := 0; i < 200; i++ {
							g.Set("dummyDom:role.dummyRole", []*Assertion{
								func() *Assertion {
									a, _ := NewAssertion("dummyAct", "dummyDom:dummyRes", "allow")
									return a
								}(),
							})
						}
						g.Set("dummyDom:role.dummyRole1", []*Assertion{
							func() *Assertion {
								a, _ := NewAssertion("dummyAct", "dummyDom:dummyRes", "deny")
								return a
							}(),
						})
						return g
					}(),
				},
				args: args{
					ctx:      context.Background(),
					domain:   "dummyDom",
					roles:    []string{"dummyRole", "dummyRole1"},
					action:   "dummyAct",
					resource: "dummyRes",
				},
				want: errors.New("policy deny: Access Check was explicitly denied"),
			},
		*/
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &policyd{
				expireMargin:     tt.fields.expireMargin,
				rolePolicies:     tt.fields.rolePolicies,
				refreshDuration:  tt.fields.refreshDuration,
				errRetryInterval: tt.fields.errRetryInterval,
				pkp:              tt.fields.pkp,
				etagCache:        tt.fields.etagCache,
				etagFlushDur:     tt.fields.etagFlushDur,
				etagExpTime:      tt.fields.etagExpTime,
				athenzURL:        tt.fields.athenzURL,
				athenzDomains:    tt.fields.athenzDomains,
				client:           tt.fields.client,
			}
			err := p.CheckPolicy(tt.args.ctx, tt.args.domain, tt.args.roles, tt.args.action, tt.args.resource)
			if err == nil {
				if tt.want != nil {
					t.Errorf("CheckPolicy error: err: nil, want: %v", tt.want)
				}
			} else {
				if tt.want == nil {
					t.Errorf("CheckPolicy error: err: %v, want: nil", err)
				} else if err.Error() != tt.want.Error() {
					t.Errorf("CheckPolicy error: err: %v, want: %v", err, tt.want)
				}
			}
		})
	}
}

func Test_policyd_fetchAndCachePolicy(t *testing.T) {
	type fields struct {
		expireMargin          time.Duration
		rolePolicies          gache.Gache
		policyExpiredDuration time.Duration
		refreshDuration       time.Duration
		errRetryInterval      time.Duration
		pkp                   pubkey.Provider
		etagCache             gache.Gache
		etagFlushDur          time.Duration
		etagExpTime           time.Duration
		athenzURL             string
		athenzDomains         []string
		client                *http.Client
	}
	type args struct {
		ctx context.Context
		g   gache.Gache
		dom string
	}
	type test struct {
		name      string
		fields    fields
		args      args
		checkFunc func(pol *policyd) error
		wantErr   bool
	}
	tests := []test{
		func() test {
			handler := http.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Add("ETag", "dummyEtag")
				w.Write([]byte(`{"signedPolicyData":{"policyData":{"domain":"dummyDom","policies":[{"name":"dummyDom:policy.dummyPol","modified":"2099-02-14T05:42:07.219Z","assertions":[{"role":"dummyDom:role.dummyRole","resource":"dummyDom:dummyRes","action":"dummyAct","effect":"ALLOW"}]}]},"zmsSignature":"dummySig","zmsKeyId":"dummyKeyID","modified":"2099-03-04T04:33:27.318Z","expires":"2099-03-12T08:11:18.729Z"},"signature":"dummySig","keyId":"dummyKeyID"}`))
				w.WriteHeader(http.StatusOK)
			}))
			srv := httptest.NewTLSServer(handler)
			g := gache.New()

			return test{
				name: "fetch policy success with updated policy",
				fields: fields{
					rolePolicies:          gache.New(),
					policyExpiredDuration: time.Minute * 30,
					athenzURL:             strings.Replace(srv.URL, "https://", "", 1),
					etagCache:             gache.New(),
					etagExpTime:           time.Minute,
					expireMargin:          time.Hour,
					client:                srv.Client(),
					pkp: func(e pubkey.AthenzEnv, id string) authcore.Verifier {
						return VerifierMock{
							VerifyFunc: func(d, s string) error {
								return nil
							},
						}
					},
				},
				args: args{
					ctx: context.Background(),
					g:   g,
					dom: "dummyDom",
				},
				checkFunc: func(pol *policyd) error {
					pols, ok := g.Get("dummyDom:role.dummyRole")
					if !ok {
						return errors.New("role policies not found")
					}
					if len(pols.([]*Assertion)) != 1 {
						return errors.New("role policies not correct")
					}

					return nil
				},
			}
		}(),
		func() test {
			handler := http.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}))
			srv := httptest.NewTLSServer(handler)
			g := gache.New()

			return test{
				name: "fetch policy failed",
				fields: fields{
					rolePolicies:          gache.New(),
					policyExpiredDuration: time.Minute * 30,
					athenzURL:             strings.Replace(srv.URL, "https://", "", 1),
					etagCache:             gache.New(),
					etagExpTime:           time.Minute,
					expireMargin:          time.Hour,
					client:                srv.Client(),
					pkp: func(e pubkey.AthenzEnv, id string) authcore.Verifier {
						return VerifierMock{
							VerifyFunc: func(d, s string) error {
								return nil
							},
						}
					},
				},
				args: args{
					ctx: context.Background(),
					g:   g,
					dom: "dummyDomain",
				},
				wantErr: true,
			}
		}(),
		func() test {
			handler := http.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Add("ETag", "dummyEtag")
				w.Write([]byte(`{"signedPolicyData":{"policyData":{"domain":"dummyDom","policies":[{"name":"dummyDom:policy.dummyPol","modified":"2099-02-14T05:42:07.219Z","assertions":[{"role":"dummyDom:role.dummyRole","resource":"","action":"dummyAct","effect":"ALLOW"}]}]},"zmsSignature":"dummySig","zmsKeyId":"dummyKeyID","modified":"2099-03-04T04:33:27.318Z","expires":"2099-03-12T08:11:18.729Z"},"signature":"dummySig","keyId":"dummyKeyID"}`))
				w.WriteHeader(http.StatusOK)
			}))
			srv := httptest.NewTLSServer(handler)

			return test{
				name: "simplifyAndCache failed",
				fields: fields{
					rolePolicies:          gache.New(),
					policyExpiredDuration: time.Minute * 30,
					athenzURL:             strings.Replace(srv.URL, "https://", "", 1),
					etagCache:             gache.New(),
					etagExpTime:           time.Minute,
					expireMargin:          time.Hour,
					client:                srv.Client(),
					pkp: func(e pubkey.AthenzEnv, id string) authcore.Verifier {
						return VerifierMock{
							VerifyFunc: func(d, s string) error {
								return nil
							},
						}
					},
				},
				args: args{
					ctx: context.Background(),
					g:   gache.New(),
					dom: "dummyDom",
				},
				wantErr: true,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &policyd{
				expireMargin:          tt.fields.expireMargin,
				rolePolicies:          tt.fields.rolePolicies,
				policyExpiredDuration: tt.fields.policyExpiredDuration,
				refreshDuration:       tt.fields.refreshDuration,
				errRetryInterval:      tt.fields.errRetryInterval,
				pkp:                   tt.fields.pkp,
				etagCache:             tt.fields.etagCache,
				etagFlushDur:          tt.fields.etagFlushDur,
				etagExpTime:           tt.fields.etagExpTime,
				athenzURL:             tt.fields.athenzURL,
				athenzDomains:         tt.fields.athenzDomains,
				client:                tt.fields.client,
			}
			if err := p.fetchAndCachePolicy(tt.args.ctx, tt.args.g, tt.args.dom); (err != nil) != tt.wantErr {
				t.Errorf("policy.fetchAndCachePolicy() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.checkFunc != nil {
				if err := tt.checkFunc(p); err != nil {
					t.Errorf("policy.fetchAndCachePolicy() error = %v", err)
				}
			}
		})
	}
}

func Test_policyd_fetchPolicy(t *testing.T) {
	type fields struct {
		expireMargin          time.Duration
		rolePolicies          gache.Gache
		policyExpiredDuration time.Duration
		refreshDuration       time.Duration
		errRetryInterval      time.Duration
		pkp                   pubkey.Provider
		etagCache             gache.Gache
		etagFlushDur          time.Duration
		etagExpTime           time.Duration
		athenzURL             string
		athenzDomains         []string
		client                *http.Client
	}
	type args struct {
		ctx    context.Context
		domain string
	}
	type test struct {
		name      string
		fields    fields
		args      args
		checkFunc func(p *policyd, sp *SignedPolicy, upd bool, err error) error
	}
	tests := []test{
		func() test {
			handler := http.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Add("ETag", "dummyEtag")
				w.Write([]byte(`{"signedPolicyData":{
					"zmsKeyId":"1",
					"Expires":"2099-12-31"
				}}`))
				w.WriteHeader(http.StatusOK)
			}))
			srv := httptest.NewTLSServer(handler)

			return test{
				name: "test fetch success",
				fields: fields{
					athenzURL:             strings.Replace(srv.URL, "https://", "", 1),
					policyExpiredDuration: time.Minute * 30,
					etagCache:             gache.New(),
					etagExpTime:           time.Minute,
					expireMargin:          time.Hour,
					client:                srv.Client(),
					pkp: func(e pubkey.AthenzEnv, id string) authcore.Verifier {
						return VerifierMock{
							VerifyFunc: func(d, s string) error {
								return nil
							},
						}
					},
				},
				args: args{
					ctx:    context.Background(),
					domain: "dummyDomain",
				},
				checkFunc: func(p *policyd, sp *SignedPolicy, upd bool, err error) error {
					if err != nil {
						return err
					}

					etag, ok := p.etagCache.Get("dummyDomain")
					if !ok {
						return errors.New("etag not set")
					}
					etagCac := etag.(*etagCache)
					if etagCac.eTag != "dummyEtag" {
						return errors.New("etag header not correct")
					}

					want := &SignedPolicy{
						util.DomainSignedPolicyData{
							SignedPolicyData: &util.SignedPolicyData{
								ZmsKeyId: "1",
							},
						},
					}

					if !cmp.Equal(etagCac.sp, sp) {
						return errors.Errorf("etag value not match, got: %v, want: %v", etag, want)
					}

					if upd == false {
						return errors.New("Invalid upd flag")
					}

					return err
				},
			}
		}(),
		func() test {
			handler := http.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			}))
			srv := httptest.NewTLSServer(handler)

			return test{
				name: "test fetch error url",
				fields: fields{
					athenzURL:             " ",
					policyExpiredDuration: time.Minute * 30,
					etagCache:             gache.New(),
					etagExpTime:           time.Minute,
					expireMargin:          time.Second,
					client:                srv.Client(),
					pkp: func(e pubkey.AthenzEnv, id string) authcore.Verifier {
						return VerifierMock{
							VerifyFunc: func(d, s string) error {
								return nil
							},
						}
					},
				},
				args: args{
					ctx:    context.Background(),
					domain: "dummy",
				},
				checkFunc: func(p *policyd, sp *SignedPolicy, upd bool, err error) error {
					if sp != nil {
						return errors.New("invalid return")
					}
					if upd != false {
						return errors.New("invalid return ")
					}
					wantErr := `error creating fetch policy request: parse https:// /domain/dummy/signed_policy_data: invalid character " " in host name`
					if err.Error() != wantErr {
						return errors.Errorf("got error: %v, want: %v", err, wantErr)
					}

					return nil
				},
			}
		}(),
		func() test {
			handler := http.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("If-None-Match") != "dummyEtag" {
					w.Header().Add("ETag", "dummyEtag")
					w.WriteHeader(http.StatusOK)
				} else {
					w.WriteHeader(http.StatusNotModified)
				}
			}))
			srv := httptest.NewTLSServer(handler)

			etagCac := gache.New()
			etagCac.Set("dummyDomain", &etagCache{
				eTag: "dummyEtag",
				sp: &SignedPolicy{
					util.DomainSignedPolicyData{
						SignedPolicyData: &util.SignedPolicyData{
							Expires: func() *rdl.Timestamp {
								t := rdl.NewTimestamp(time.Now().Add(time.Hour))
								return &t
							}(),
						},
					},
				},
			})

			return test{
				name: "test etag exists but not modified",
				fields: fields{
					athenzURL:             strings.Replace(srv.URL, "https://", "", 1),
					policyExpiredDuration: time.Minute * 30,
					etagCache:             etagCac,
					etagExpTime:           time.Minute,
					expireMargin:          time.Second,
					client:                srv.Client(),
					pkp: func(e pubkey.AthenzEnv, id string) authcore.Verifier {
						return VerifierMock{
							VerifyFunc: func(d, s string) error {
								return nil
							},
						}
					},
				},
				args: args{
					ctx:    context.Background(),
					domain: "dummyDomain",
				},
				checkFunc: func(p *policyd, sp *SignedPolicy, upd bool, err error) error {
					if err != nil {
						return err
					}

					etag, ok := p.etagCache.Get("dummyDomain")
					if !ok {
						return errors.New("etag not set")
					}
					etagCac := etag.(*etagCache)
					if etagCac.eTag != "dummyEtag" {
						return errors.New("etag header not correct")
					}

					if etagCac.sp != sp {
						return errors.Errorf("etag value not match, got: %v, want: %v", etag, sp)
					}

					if upd != false {
						return errors.New("Invalid upd flag")
					}

					return err
				},
			}
		}(),
		func() test {
			handler := http.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("If-None-Match") == "dummyOldEtag" {
					w.Header().Add("ETag", "dummyNewEtag")
					w.Write([]byte(`{"signedPolicyData":
					{
						"zmsKeyId":"dummyNewId",
						"Expires":"2099-12-31"
					}}`))
					w.WriteHeader(http.StatusOK)
				} else {
					w.WriteHeader(http.StatusNotModified)
				}
			}))
			srv := httptest.NewTLSServer(handler)

			etagCac := gache.New()
			etagCac.Set("dummyDomain", &etagCache{
				eTag: "dummyOldEtag",
				sp: &SignedPolicy{
					util.DomainSignedPolicyData{
						SignedPolicyData: &util.SignedPolicyData{
							Expires: &rdl.Timestamp{
								time.Now().Add(time.Hour).UTC(),
							},
						},
					},
				},
			})

			return test{
				name: "test etag exists but modified",
				fields: fields{
					athenzURL:             strings.Replace(srv.URL, "https://", "", 1),
					policyExpiredDuration: time.Minute * 30,
					etagCache:             etagCac,
					etagExpTime:           time.Minute,
					expireMargin:          time.Second,
					client:                srv.Client(),
					pkp: func(e pubkey.AthenzEnv, id string) authcore.Verifier {
						return VerifierMock{
							VerifyFunc: func(d, s string) error {
								return nil
							},
						}
					},
				},
				args: args{
					ctx:    context.Background(),
					domain: "dummyDomain",
				},
				checkFunc: func(p *policyd, sp *SignedPolicy, upd bool, err error) error {
					if err != nil {
						return err
					}

					etag, ok := p.etagCache.Get("dummyDomain")
					if !ok {
						return errors.New("etag not set")
					}
					etagCac := etag.(*etagCache)
					if etagCac.eTag != "dummyNewEtag" {
						return errors.New("etag header not correct")
					}

					if !cmp.Equal(etagCac.sp, sp) {
						return errors.Errorf("etag value not match, got: %v, want: %v", etagCac, sp)
					}

					if upd != true {
						return errors.New("Invalid upd flag")
					}

					return err
				},
			}
		}(),
		func() test {
			handler := http.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			}))
			srv := httptest.NewTLSServer(handler)

			return test{
				name: "test fetch error make https request",
				fields: fields{
					athenzURL:             "dummyURL",
					policyExpiredDuration: time.Minute * 30,
					etagCache:             gache.New(),
					etagExpTime:           time.Minute,
					expireMargin:          time.Hour,
					client:                srv.Client(),
					pkp: func(e pubkey.AthenzEnv, id string) authcore.Verifier {
						return VerifierMock{
							VerifyFunc: func(d, s string) error {
								return nil
							},
						}
					},
				},
				args: args{
					ctx:    context.Background(),
					domain: "dummyDomain",
				},
				checkFunc: func(p *policyd, sp *SignedPolicy, upd bool, err error) error {
					if sp != nil {
						return errors.Errorf("sp should be nil")
					}
					if upd != false {
						return errors.New("Invalid upd flag")
					}
					wantErr := "error making request: Get https://dummyURL/domain/dummyDomain/signed_policy_data: dial tcp: lookup dummyURL"
					if !strings.HasPrefix(err.Error(), wantErr) {
						return errors.Errorf("invalid error, got: %v, want: %v", err, wantErr)
					}

					return nil
				},
			}
		}(),
		func() test {
			handler := http.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}))
			srv := httptest.NewTLSServer(handler)

			return test{
				name: "test fetch error return not ok",
				fields: fields{
					athenzURL:             strings.Replace(srv.URL, "https://", "", 1),
					policyExpiredDuration: time.Minute * 30,
					etagCache:             gache.New(),
					etagExpTime:           time.Minute,
					expireMargin:          time.Hour,
					client:                srv.Client(),
					pkp: func(e pubkey.AthenzEnv, id string) authcore.Verifier {
						return VerifierMock{
							VerifyFunc: func(d, s string) error {
								return nil
							},
						}
					},
				},
				args: args{
					ctx:    context.Background(),
					domain: "dummyDomain",
				},
				checkFunc: func(p *policyd, sp *SignedPolicy, upd bool, err error) error {
					if sp != nil {
						return errors.Errorf("sp should be nil")
					}
					if upd != false {
						return errors.New("Invalid upd flag")
					}
					wantErr := "error fetching policy data: Error fetching athenz policy"
					if err.Error() != wantErr {
						return errors.Errorf("invalid error, got: %v, want: %v", err, wantErr)
					}

					return nil
				},
			}
		}(),
		func() test {
			handler := http.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(""))
			}))
			srv := httptest.NewTLSServer(handler)

			return test{
				name: "test fetch error decode policy",
				fields: fields{
					athenzURL:             strings.Replace(srv.URL, "https://", "", 1),
					policyExpiredDuration: time.Minute * 30,
					etagCache:             gache.New(),
					etagExpTime:           time.Minute,
					expireMargin:          time.Hour,
					client:                srv.Client(),
					pkp: func(e pubkey.AthenzEnv, id string) authcore.Verifier {
						return VerifierMock{
							VerifyFunc: func(d, s string) error {
								return nil
							},
						}
					},
				},
				args: args{
					ctx:    context.Background(),
					domain: "dummyDomain",
				},
				checkFunc: func(p *policyd, sp *SignedPolicy, upd bool, err error) error {
					if sp != nil {
						return errors.Errorf("sp should be nil")
					}
					if upd != false {
						return errors.New("Invalid upd flag")
					}
					wantErr := "error decode response: EOF"
					if err.Error() != wantErr {
						return errors.Errorf("invalid error, got: %v, want: %v", err, wantErr)
					}

					return nil
				},
			}
		}(),
		func() test {
			handler := http.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"signedPolicyData":
				{
					"zmsKeyId":"1",
					"Expires":"2099-12-31"
				}}`))
			}))
			srv := httptest.NewTLSServer(handler)

			return test{
				name: "test fetch verify error",
				fields: fields{
					athenzURL:             strings.Replace(srv.URL, "https://", "", 1),
					policyExpiredDuration: time.Minute * 30,
					etagCache:             gache.New(),
					etagExpTime:           time.Minute,
					expireMargin:          time.Hour,
					client:                srv.Client(),
					pkp: func(e pubkey.AthenzEnv, id string) authcore.Verifier {
						return VerifierMock{
							VerifyFunc: func(d, s string) error {
								return errors.New("error")
							},
						}
					},
				},
				args: args{
					ctx:    context.Background(),
					domain: "dummyDomain",
				},
				checkFunc: func(p *policyd, sp *SignedPolicy, upd bool, err error) error {
					if sp != nil {
						return errors.Errorf("sp should be nil")
					}
					if upd != false {
						return errors.New("Invalid upd flag")
					}
					wantErr := "error verify policy data: error verify signature: error"
					if err.Error() != wantErr {
						return errors.Errorf("invalid error, got: %v, want: %v", err, wantErr)
					}

					return nil
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &policyd{
				expireMargin:          tt.fields.expireMargin,
				rolePolicies:          tt.fields.rolePolicies,
				policyExpiredDuration: tt.fields.policyExpiredDuration,
				refreshDuration:       tt.fields.refreshDuration,
				errRetryInterval:      tt.fields.errRetryInterval,
				pkp:                   tt.fields.pkp,
				etagCache:             tt.fields.etagCache,
				etagFlushDur:          tt.fields.etagFlushDur,
				etagExpTime:           tt.fields.etagExpTime,
				athenzURL:             tt.fields.athenzURL,
				athenzDomains:         tt.fields.athenzDomains,
				client:                tt.fields.client,
			}
			got, got1, err := p.fetchPolicy(tt.args.ctx, tt.args.domain)

			if err := tt.checkFunc(p, got, got1, err); err != nil {
				t.Errorf("policy.fetchPolicy() error = %v", err)
			}
		})
	}
}

func Test_simplifyAndCachePolicy(t *testing.T) {
	type args struct {
		ctx context.Context
		rp  gache.Gache
		sp  *SignedPolicy
	}
	type test struct {
		name      string
		args      args
		checkFunc func() error
		wantErr   bool
	}

	checkAssertion := func(got *Assertion, action, res, eff string) error {
		want, _ := NewAssertion(action, res, eff)
		if !reflect.DeepEqual(got, want) {
			return errors.Errorf("got: %v, want: %v", got, want)
		}
		return nil
	}
	tests := []test{
		func() test {
			rp := gache.New()
			return test{
				name: "cache success with data",
				args: args{
					ctx: context.Background(),
					rp:  rp,
					sp: &SignedPolicy{
						util.DomainSignedPolicyData{
							SignedPolicyData: &util.SignedPolicyData{
								Expires: &rdl.Timestamp{
									time.Now().Add(time.Hour * 99999).UTC(),
								},
								PolicyData: &util.PolicyData{
									Policies: []*util.Policy{
										{
											Assertions: []*util.Assertion{
												{
													Role:     "dummyDom:role.dummyRole",
													Action:   "dummyAct",
													Resource: "dummyDom:dummyRes",
													Effect:   "dummyEff",
												},
											},
										},
										{
											Assertions: []*util.Assertion{
												{
													Role:     "dummyDom:role.dummyRole",
													Action:   "dummyAct1",
													Resource: "dummyDom:dummyRes1",
													Effect:   "dummyEff1",
												},
											},
										},
										{
											Assertions: []*util.Assertion{
												{
													Role:     "dummyDom2:role.dummyRole2",
													Action:   "dummyAct2",
													Resource: "dummyDom2:dummyRes2",
													Effect:   "allow",
												},
											},
										},
									},
								},
							},
						},
					},
				},
				checkFunc: func() error {
					if len(rp.ToRawMap(context.Background())) != 2 {
						return errors.Errorf("invalid length role policies 2, role policies: %v", rp.ToRawMap(context.Background()))
					}

					gotRp1, ok := rp.Get("dummyDom:role.dummyRole")
					if !ok {
						return errors.New("cannot simplify and cache data")
					}
					gotAsss1 := gotRp1.([]*Assertion)
					if len(gotAsss1) != 2 {
						return errors.Errorf("invalid length asss 1, got: %v", gotAsss1)
					}
					hv1, hv2 := false, false
					for _, asss := range gotAsss1 { // because it is go func, we can not control the order of slice
						if err := checkAssertion(asss, "dummyAct", "dummyDom:dummyRes", "dummyEff"); err != nil {
							hv1 = true
						}

						if err := checkAssertion(asss, "dummyAct1", "dummyDom:dummyRes1", "dummyEff1"); err != nil {
							hv2 = true
						}
					}
					if !hv1 && !hv2 {
						return errors.Errorf("hv1: %v, hv2: %v", hv1, hv2)
					}

					gotRp2, ok := rp.Get("dummyDom2:role.dummyRole2")
					if !ok {
						return errors.New("cannot simplify and cache data")
					}
					gotAsss2 := gotRp2.([]*Assertion)
					if len(gotAsss2) != 1 {
						return errors.New("dummyDom2:role.dummyRole2 invalid length")
					}

					return checkAssertion(gotAsss2[0], "dummyAct2", "dummyDom2:dummyRes2", "allow")
				},
				wantErr: false,
			}
		}(),

		func() test {
			rp := gache.New()
			ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Nanosecond*5))
			return test{
				name: "test context done",
				args: args{
					ctx: ctx,
					rp:  rp,
					sp: &SignedPolicy{
						util.DomainSignedPolicyData{
							SignedPolicyData: &util.SignedPolicyData{
								Expires: &rdl.Timestamp{
									time.Now().Add(time.Hour * 99999).UTC(),
								},
								PolicyData: &util.PolicyData{
									Policies: []*util.Policy{
										{
											Assertions: []*util.Assertion{
												{
													Role:     "dummyDom:role.dummyRole",
													Action:   "dummyAct",
													Resource: "dummyDom:dummyRes",
													Effect:   "dummyEff",
												},
											},
										},
										{
											Assertions: []*util.Assertion{
												{
													Role:     "dummyDom:role.dummyRole",
													Action:   "dummyAct1",
													Resource: "dummyDom:dummyRes1",
													Effect:   "dummyEff1",
												},
											},
										},
										{
											Assertions: []*util.Assertion{
												{
													Role:     "dummyDom2:role.dummyRole2",
													Action:   "dummyAct2",
													Resource: "dummyDom2:dummyRes2",
													Effect:   "allow",
												},
											},
										},
									},
								},
							},
						},
					},
				},
				checkFunc: func() error {
					cancel()
					return nil
				},
				wantErr: true,
			}
		}(),

		func() test {
			rp := gache.New()
			return test{
				name: "cache deny overwrite allow",
				args: args{
					ctx: context.Background(),
					rp:  rp,
					sp: &SignedPolicy{
						util.DomainSignedPolicyData{
							SignedPolicyData: &util.SignedPolicyData{
								Expires: &rdl.Timestamp{
									time.Now().Add(time.Hour * 99999).UTC(),
								},
								PolicyData: &util.PolicyData{
									Policies: []*util.Policy{
										{
											Assertions: []*util.Assertion{
												{
													Role:     "dummyDom:role.dummyRole",
													Action:   "dummyAct",
													Resource: "dummyDom:dummyRes",
													Effect:   "allow",
												},
												{
													Role:     "dummyDom:role.dummyRole",
													Action:   "dummyAct",
													Resource: "dummyDom:dummyRes",
													Effect:   "allow",
												},
											},
										},
										{
											Assertions: []*util.Assertion{
												{
													Role:     "dummyDom:role.dummyRole",
													Action:   "dummyAct",
													Resource: "dummyDom:dummyRes",
													Effect:   "deny",
												},
											},
										},
										{
											Assertions: []*util.Assertion{
												{
													Role:     "dummyDom:role.dummyRole",
													Action:   "dummyAct",
													Resource: "dummyDom:dummyRes",
													Effect:   "allow",
												},
												{
													Role:     "dummyDom:role.dummyRole",
													Action:   "dummyAct",
													Resource: "dummyDom:dummyRes",
													Effect:   "deny",
												},
											},
										},
									},
								},
							},
						},
					},
				},
				checkFunc: func() error {
					if len(rp.ToRawMap(context.Background())) != 1 {
						return errors.Errorf("invalid length role policies 1, role policies: %v", rp.ToRawMap(context.Background()))
					}

					gotRp1, ok := rp.Get("dummyDom:role.dummyRole")
					if !ok {
						return errors.New("cannot simplify and cache data")
					}
					gotAsss1 := gotRp1.([]*Assertion)
					if len(gotAsss1) != 1 {
						return errors.Errorf("invalid length asss 1, got: %v", gotAsss1)
					}
					if gotAsss1[0].Effect == nil {
						return errors.Errorf("Deny policy did not overwrite allow policy")
					}

					return nil
				},
				wantErr: false,
			}
		}(),

		func() test {
			rp := gache.New()
			return test{
				name: "cache success with no data",
				args: args{
					ctx: context.Background(),
					rp:  rp,
					sp: &SignedPolicy{
						util.DomainSignedPolicyData{
							SignedPolicyData: &util.SignedPolicyData{
								PolicyData: &util.PolicyData{
									Policies: []*util.Policy{},
								},
							},
						},
					},
				},
				checkFunc: func() error {
					if len(rp.ToRawMap(context.Background())) != 0 {
						return errors.Errorf("invalid length role policies 0, role policies: %v", rp.ToRawMap(context.Background()))
					}
					return nil
				},
				wantErr: false,
			}
		}(),
		func() test {
			return test{
				name: "cache failed with invalid assertion",
				args: args{
					ctx: context.Background(),
					rp:  gache.New(),
					sp: &SignedPolicy{
						util.DomainSignedPolicyData{
							SignedPolicyData: &util.SignedPolicyData{
								Expires: &rdl.Timestamp{
									time.Now().Add(time.Hour).UTC(),
								},
								PolicyData: &util.PolicyData{
									Policies: []*util.Policy{
										{
											Assertions: []*util.Assertion{
												{
													Role:     "dummyRole",
													Action:   "dummyAct",
													Resource: "dummyRes",
													Effect:   "allow",
												},
											},
										},
									},
								},
							},
						},
					},
				},
				wantErr: true,
			}
		}(),
		func() test {
			rp := gache.New()
			return test{
				name: "cache success with no data",
				args: args{
					ctx: context.Background(),
					rp:  rp,
					sp: &SignedPolicy{
						util.DomainSignedPolicyData{
							SignedPolicyData: &util.SignedPolicyData{
								PolicyData: &util.PolicyData{
									Policies: []*util.Policy{},
								},
							},
						},
					},
				},
				checkFunc: func() error {
					if len(rp.ToRawMap(context.Background())) != 0 {
						return errors.Errorf("invalid length role policies 0, role policies: %v", rp.ToRawMap(context.Background()))
					}
					return nil
				},
				wantErr: false,
			}
		}(),
		func() test {
			return test{
				name: "cache failed with invalid assertion",
				args: args{
					ctx: context.Background(),
					sp: &SignedPolicy{
						util.DomainSignedPolicyData{
							SignedPolicyData: &util.SignedPolicyData{
								Expires: &rdl.Timestamp{
									time.Now().Add(time.Hour).UTC(),
								},
								PolicyData: &util.PolicyData{
									Policies: []*util.Policy{
										{
											Assertions: []*util.Assertion{
												{
													Role:     "dummyRole",
													Action:   "dummyAct",
													Resource: "dummyRes",
													Effect:   "allow",
												},
											},
										},
									},
								},
							},
						},
					},
				},
				wantErr: true,
			}
		}(),
		func() test {
			rp := gache.New()

			rp.Set("dummyDom:role.dummyRole", []*Assertion{
				func() *Assertion {
					a, _ := NewAssertion("dummyAct", "dummyDom:dummyRes", "dummyEff")
					return a
				}(),
			})
			return test{
				name: "cache can append new assertion",
				args: args{
					ctx: context.Background(),
					rp:  rp,
					sp: &SignedPolicy{
						util.DomainSignedPolicyData{
							SignedPolicyData: &util.SignedPolicyData{
								Expires: &rdl.Timestamp{
									time.Now().Add(time.Hour).UTC(),
								},
								PolicyData: &util.PolicyData{
									Policies: []*util.Policy{
										{
											Assertions: []*util.Assertion{
												{
													Role:     "dummyDom:role.dummyRole",
													Action:   "dummyAct1",
													Resource: "dummyDom1:dummyRes1",
													Effect:   "allow1",
												},
											},
										},
									},
								},
							},
						},
					},
				},
				checkFunc: func() error {
					if len(rp.ToRawMap(context.Background())) != 1 {
						return errors.Errorf("invalid role policies length")
					}

					gotAsss, ok := rp.Get("dummyDom:role.dummyRole")
					if !ok {
						return errors.New("cannot find dummyDom:role.dummyRole")
					}

					asss := gotAsss.([]*Assertion)
					if len(asss) != 2 {
						return errors.New("Invalid asss length")
					}

					if err := checkAssertion(asss[0], "dummyAct", "dummyDom:dummyRes", "dummyEff1"); err != nil {
						return err
					}

					return checkAssertion(asss[1], "dummyAct1", "dummyDom1:dummyRes1", "allow1")
				},
				wantErr: false,
			}
		}(),
		/*
			func() test {
				rp := gache.New()

				rp.Set("dummyDom:role.dummyRole", []*Assertion{
					func() *Assertion {
						a, _ := NewAssertion("dummyAct", "dummyDom:dummyRes", "dummyEff")
						return a
					}(),
				})
				return test{
					name: "cache delete",
					fields: fields{
						rolePolicies:          rp,
						policyExpiredDuration: time.Minute * 30,
					},
					args: args{
						ctx: context.Background(),
						rp:  rp,
						sp: &SignedPolicy{
							util.DomainSignedPolicyData{
								SignedPolicyData: &util.SignedPolicyData{
									Expires: &rdl.Timestamp{
										time.Now().Add(time.Hour).UTC(),
									},
									PolicyData: &util.PolicyData{
										Policies: []*util.Policy{
											{
												Assertions: []*util.Assertion{
													{
														Role:     "dummyDom1:role.dummyRole1",
														Action:   "dummyAct1",
														Resource: "dummyDom1:dummyRes1",
														Effect:   "allow1",
													},
												},
											},
										},
									},
								},
							},
						},
					},
					checkFunc: func(pol *policyd) error {
						// check if old policy exists
						_, ok := pol.rolePolicies.Get("dummyDom:role.dummyRole")
						if ok {
							return errors.New("role policy found")
						}

						// check new policy exist
						if len(pol.rolePolicies.ToRawMap(context.Background())) != 1 {
							return errors.Errorf("invalid role policies length")
						}

						gotAsss, ok := pol.rolePolicies.Get("dummyDom1:role.dummyRole1")
						if !ok {
							return errors.New("cannot find dummyDom1:role.dummyRole1")
						}

						asss := gotAsss.([]*Assertion)
						if len(asss) != 1 {
							return errors.New("Invalid asss length")
						}

						ass := asss[0]
						return checkAssertion(ass, "dummyAct1", "dummyDom1:dummyRes1", "allow1")
					},
					wantErr: false,
				}
			}(),
		*/

		func() test {
			rp := gache.New()
			return test{
				name: "cache success with 100x100 data",
				args: args{
					ctx: context.Background(),
					rp:  rp,
					sp: &SignedPolicy{
						util.DomainSignedPolicyData{
							SignedPolicyData: &util.SignedPolicyData{
								Expires: &rdl.Timestamp{
									time.Now().Add(time.Hour).UTC(),
								},
								PolicyData: &util.PolicyData{
									Policies: func() []*util.Policy {
										var pols []*util.Policy

										for j := 0; j < 100; j++ {
											pols = append(pols, &util.Policy{
												Assertions: func() []*util.Assertion {
													var asss []*util.Assertion
													for i := 0; i < 100; i++ {
														asss = append(asss, &util.Assertion{
															Role:     fmt.Sprintf("dummyDom%d:role.dummyRole", j),
															Action:   "dummyAct",
															Resource: fmt.Sprintf("dummyDom%d:dummyRes%d", j, i),
															Effect:   "dummyEff",
														})
													}
													return asss
												}(),
											})
										}
										return pols
									}(),
								},
							},
						},
					},
				},
				checkFunc: func() error {
					if len(rp.ToRawMap(context.Background())) != 100 {
						return errors.New("invalid length role policies 100")
					}

					var err error
					rp.Foreach(context.Background(), func(k string, val interface{}, exp int64) bool {
						//glg.Debugf("key: %s, val: %v", k, val)
						if len(val.([]*Assertion)) != 100 {
							err = errors.Errorf("invalid length asss 100, error: %v", k)
						}
						return true
					})

					return err
				},
				wantErr: false,
			}
		}(),
		func() test {
			rp := gache.New()
			return test{
				name: "cache success with no race condition with 100x100 data",
				args: args{
					ctx: context.Background(),
					rp:  rp,
					sp: &SignedPolicy{
						util.DomainSignedPolicyData{
							SignedPolicyData: &util.SignedPolicyData{
								Expires: &rdl.Timestamp{
									time.Now().Add(time.Hour).UTC(),
								},
								PolicyData: &util.PolicyData{
									Policies: func() []*util.Policy {
										var pols []*util.Policy

										for j := 0; j < 100; j++ {
											pols = append(pols, &util.Policy{
												Assertions: func() []*util.Assertion {
													var asss []*util.Assertion
													for i := 0; i < 100; i++ {
														asss = append(asss, &util.Assertion{
															Role:     "dummyDom:role.dummyRole",
															Action:   "dummyAct",
															Resource: fmt.Sprintf("dummyDom%d:dummyRes%d", j, i),
															Effect:   "dummyEff",
														})
													}
													return asss
												}(),
											})
										}
										return pols
									}(),
								},
							},
						},
					},
				},
				checkFunc: func() error {
					if len(rp.ToRawMap(context.Background())) != 1 {
						return errors.New("invalid length role policies 1")
					}

					var err error
					rp.Foreach(context.Background(), func(k string, val interface{}, exp int64) bool {
						//glg.Debugf("key: %s, val: %v", k, val)
						if len(val.([]*Assertion)) != 10000 {
							err = errors.Errorf("invalid length asss 100, error: %v", k)
						}
						return true
					})

					return err
				},
				wantErr: false,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := simplifyAndCachePolicy(tt.args.ctx, tt.args.rp, tt.args.sp); (err != nil) != tt.wantErr {
				t.Errorf("simplifyAndCachePolicy() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.checkFunc != nil {
				if err := tt.checkFunc(); err != nil {
					t.Errorf("simplifyAndCachePolicy() error = %v", err)
				}
			}
		})
	}
}

func Test_policyd_GetPolicyCache(t *testing.T) {
	type fields struct {
		expireMargin          time.Duration
		rolePolicies          gache.Gache
		policyExpiredDuration time.Duration
		refreshDuration       time.Duration
		errRetryInterval      time.Duration
		pkp                   pubkey.Provider
		etagCache             gache.Gache
		etagFlushDur          time.Duration
		etagExpTime           time.Duration
		athenzURL             string
		athenzDomains         []string
		client                *http.Client
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
			name: "get empty policy cache success",
			fields: fields{
				rolePolicies: func() gache.Gache {
					g := gache.New()
					return g
				}(),
			},
			args: args{
				ctx: context.Background(),
			},
			want: make(map[string]interface{}),
		},
		{
			name: "get policy cache success",
			fields: fields{
				rolePolicies: func() gache.Gache {
					g := gache.New()
					g.Set("key", "value")
					return g
				}(),
			},
			args: args{
				ctx: context.Background(),
			},
			want: map[string]interface{}{
				"key": "value",
			},
		},
		{
			name: "get policy cache without expired success",
			fields: fields{
				rolePolicies: func() gache.Gache {
					g := gache.New()
					g.SetWithExpire("key", "value", 1*time.Nanosecond)
					time.Sleep(5 * time.Millisecond)
					g.DeleteExpired(context.Background())
					return g
				}(),
			},
			args: args{
				ctx: context.Background(),
			},
			want: make(map[string]interface{}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &policyd{
				expireMargin:          tt.fields.expireMargin,
				rolePolicies:          tt.fields.rolePolicies,
				policyExpiredDuration: tt.fields.policyExpiredDuration,
				refreshDuration:       tt.fields.refreshDuration,
				errRetryInterval:      tt.fields.errRetryInterval,
				pkp:                   tt.fields.pkp,
				etagCache:             tt.fields.etagCache,
				etagFlushDur:          tt.fields.etagFlushDur,
				etagExpTime:           tt.fields.etagExpTime,
				athenzURL:             tt.fields.athenzURL,
				athenzDomains:         tt.fields.athenzDomains,
				client:                tt.fields.client,
			}
			if got := p.GetPolicyCache(tt.args.ctx); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("policyd.GetPolicyCache() = %+v, want %v", got, tt.want)
			}
		})
	}
}
