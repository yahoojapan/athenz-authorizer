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
	"math"
	"net/http"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/ardielle/ardielle-go/rdl"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/kpango/fastime"
	"github.com/kpango/gache"
	"github.com/pkg/errors"
	"github.com/yahoo/athenz/utils/zpe-updater/util"
	"github.com/yahoojapan/athenz-authorizer/v2/pubkey"
)

func TestNew(t *testing.T) {
	gacheCmp := cmp.Comparer(func(x, y gache.Gache) bool {
		ctx := context.Background()
		return cmp.Equal(x.ToRawMap(ctx), y.ToRawMap(ctx), cmpopts.EquateEmpty())
	})
	fetcherCmp := cmp.Comparer(func(x, y Fetcher) bool {
		return x.Domain() == y.Domain()
	})
	type args struct {
		opts []Option
	}
	tests := []struct {
		name    string
		args    args
		want    Daemon
		wantErr string
	}{
		{
			name: "new success",
			args: args{
				opts: []Option{},
			},
			want: &policyd{
				rolePolicies:          gache.New(),
				expireMargin:          3 * time.Hour,
				policyExpiredDuration: 1 * time.Minute,
				refreshDuration:       30 * time.Minute,
				errRetryInterval:      1 * time.Minute,
				client:                http.DefaultClient,
			},
			wantErr: "",
		},
		{
			name: "new success with options",
			args: args{
				opts: []Option{WithExpireMargin("5s")},
			},
			want: &policyd{
				rolePolicies:          gache.New(),
				expireMargin:          5 * time.Second,
				policyExpiredDuration: 1 * time.Minute,
				refreshDuration:       30 * time.Minute,
				errRetryInterval:      1 * time.Minute,
				client:                http.DefaultClient,
			},
			wantErr: "",
		},
		{
			name: "new success, domains with fetchers",
			args: args{
				opts: []Option{WithAthenzDomains("dom1", "dom2")},
			},
			want: &policyd{
				rolePolicies:          gache.New(),
				expireMargin:          3 * time.Hour,
				policyExpiredDuration: 1 * time.Minute,
				refreshDuration:       30 * time.Minute,
				errRetryInterval:      1 * time.Minute,
				client:                http.DefaultClient,
				athenzDomains:         []string{"dom1", "dom2"},
				fetchers: map[string]Fetcher{
					"dom1": &fetcher{domain: "dom1"},
					"dom2": &fetcher{domain: "dom2"},
				},
			},
			wantErr: "",
		},
		{
			name: "new fail, option error",
			args: args{
				opts: []Option{
					func(*policyd) error { return errors.New("option error") },
				},
			},
			want:    nil,
			wantErr: "error create policyd: option error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.args.opts...)
			if (err == nil && tt.wantErr != "") || (err != nil && err.Error() != tt.wantErr) {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			options := []cmp.Option{gacheCmp, fetcherCmp, cmp.AllowUnexported(policyd{}), cmpopts.EquateEmpty()}
			if !cmp.Equal(got, tt.want, options...) {
				t.Errorf("New() = %v, want %v", got, tt.want)
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
		athenzURL             string
		athenzDomains         []string
		fetchers              map[string]Fetcher
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
			domain := "dummyDom"
			sp := &SignedPolicy{
				util.DomainSignedPolicyData{
					KeyId:     "dummyKeyID",
					Signature: "dummySig",
					SignedPolicyData: &util.SignedPolicyData{
						ZmsKeyId:     "dummyKeyID",
						ZmsSignature: "dummySig",
						Modified:     &rdl.Timestamp{Time: fastime.Now()},
						Expires:      &rdl.Timestamp{Time: fastime.Now().Add(time.Hour)},
						PolicyData: &util.PolicyData{
							Domain: "dummyDom",
							Policies: []*util.Policy{
								{
									Name:     "dummyDom:policy.dummyPol",
									Modified: &rdl.Timestamp{Time: fastime.Now()},
									Assertions: []*util.Assertion{
										{
											Role:     "dummyDom:role.dummyRole",
											Action:   "dummyAct",
											Resource: "dummyDom:dummyRes",
											Effect:   "ALLOW",
										},
									},
								},
							},
						},
					},
				},
			}
			fetchers := map[string]Fetcher{
				"dummyDom": &fetcherMock{
					domainMock: func() string { return domain },
					fetchWithRetryMock: func(context.Context) (*SignedPolicy, error) {
						return sp, nil
					},
				},
			}
			ctx, cancel := context.WithCancel(context.Background())

			return test{
				name: "Start success",
				fields: fields{
					rolePolicies:          gache.New(),
					policyExpiredDuration: time.Minute * 30,
					refreshDuration:       time.Second,
					expireMargin:          time.Hour,
					athenzDomains:         []string{domain},
					fetchers:              fetchers,
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
					return nil
				},
				afterFunc: func() {
					cancel()
				},
			}
		}(),
		func() test {
			domain := "dummyDom"
			sp := &SignedPolicy{
				util.DomainSignedPolicyData{
					KeyId:     "dummyKeyID",
					Signature: "dummySig",
					SignedPolicyData: &util.SignedPolicyData{
						ZmsKeyId:     "dummyKeyID",
						ZmsSignature: "dummySig",
						Modified:     &rdl.Timestamp{Time: fastime.Now()},
						Expires:      &rdl.Timestamp{Time: fastime.Now().Add(time.Hour)},
						PolicyData: &util.PolicyData{
							Domain: "dummyDom",
							Policies: []*util.Policy{
								{
									Name:     "dummyDom:policy.dummyPol",
									Modified: &rdl.Timestamp{Time: fastime.Now()},
									Assertions: []*util.Assertion{
										{
											Role:     "dummyDom:role.dummyRole",
											Effect:   "ALLOW",
											Action:   "",
											Resource: "",
										},
									},
								},
							},
						},
					},
				},
			}
			c := 0
			fetchers := map[string]Fetcher{
				"dummyDom": &fetcherMock{
					domainMock: func() string { return domain },
					fetchWithRetryMock: func(context.Context) (*SignedPolicy, error) {
						c++
						a := sp.SignedPolicyData.PolicyData.Policies[0].Assertions[0]
						a.Action = fmt.Sprintf("dummyAct%d", c)
						a.Resource = fmt.Sprintf("dummyDom:dummyRes%d", c)
						return sp, nil
					},
				},
			}
			ctx, cancel := context.WithCancel(context.Background())

			return test{
				name: "Start can update cache",
				fields: fields{
					rolePolicies:          gache.New(),
					policyExpiredDuration: time.Minute * 30,
					refreshDuration:       time.Millisecond * 30,
					expireMargin:          time.Hour,
					athenzDomains:         []string{domain},
					fetchers:              fetchers,
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

					return nil
				},
				afterFunc: func() {
					cancel()
				},
			}
		}(),
		func() test {
			domain := "dummyDom"
			sp := &SignedPolicy{
				util.DomainSignedPolicyData{
					KeyId:     "dummyKeyID",
					Signature: "dummySig",
					SignedPolicyData: &util.SignedPolicyData{
						ZmsKeyId:     "dummyKeyID",
						ZmsSignature: "dummySig",
						Modified:     &rdl.Timestamp{Time: fastime.Now()},
						Expires:      &rdl.Timestamp{Time: fastime.Now().Add(time.Hour)},
						PolicyData: &util.PolicyData{
							Domain: "dummyDom",
							Policies: []*util.Policy{
								{
									Name:     "dummyDom:policy.dummyPol",
									Modified: &rdl.Timestamp{Time: fastime.Now()},
									Assertions: []*util.Assertion{
										{
											Role:     "dummyDom:role.dummyRole",
											Effect:   "ALLOW",
											Action:   "",
											Resource: "",
										},
									},
								},
							},
						},
					},
				},
			}
			c := 0
			fetchers := map[string]Fetcher{
				"dummyDom": &fetcherMock{
					domainMock: func() string { return domain },
					fetchWithRetryMock: func(context.Context) (*SignedPolicy, error) {
						a := sp.SignedPolicyData.PolicyData.Policies[0].Assertions[0]
						c++
						if c < 3 {
							return nil, errors.New("fetchWithRetryMock error")
						}
						a.Action = fmt.Sprintf("dummyAct%d", c)
						a.Resource = fmt.Sprintf("dummyDom:dummyRes%d", c)
						return sp, nil
					},
				},
			}
			ctx, cancel := context.WithCancel(context.Background())

			return test{
				name: "Start retry update",
				fields: fields{
					rolePolicies:          gache.New(),
					policyExpiredDuration: time.Minute * 30,
					refreshDuration:       time.Minute,
					errRetryInterval:      time.Millisecond * 5,
					expireMargin:          time.Hour,
					athenzDomains:         []string{domain},
					fetchers:              fetchers,
				},
				args: args{
					ctx: ctx,
				},
				checkFunc: func(p *policyd, ch <-chan error) error {
					time.Sleep(time.Millisecond * 300)
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
				athenzURL:             tt.fields.athenzURL,
				athenzDomains:         tt.fields.athenzDomains,
				fetchers:              tt.fields.fetchers,
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
		athenzURL             string
		athenzDomains         []string
		client                *http.Client
		fetchers              map[string]Fetcher
	}
	type args struct {
		ctx context.Context
	}
	type test struct {
		name    string
		fields  fields
		args    args
		wantErr string
		wantRps map[string]interface{}
	}
	tests := []test{
		func() (t test) {
			t.name = "cancelled context, no actions"

			// dummy values
			domain := "dummyDom"
			fetchers := make(map[string]Fetcher)
			fetchers[domain] = &fetcherMock{
				domainMock: func() string { return domain },
				fetchWithRetryMock: func(context.Context) (*SignedPolicy, error) {
					return nil, errors.New("fetchWithRetryMock executed")
				},
			}
			ctx, cancel := context.WithCancel(context.Background())

			// prepare test
			cancel()
			t.fields = fields{
				rolePolicies:  gache.New(),
				athenzDomains: []string{domain},
				fetchers:      fetchers,
			}
			t.args = args{
				ctx: ctx,
			}

			// want
			t.wantErr = context.Canceled.Error()
			t.wantRps = make(map[string]interface{})
			return t
		}(),
		func() (t test) {
			t.name = "Update policy success"

			// dummy values
			domain := "dummyDom"
			fetchers := make(map[string]Fetcher)
			sp := &SignedPolicy{
				util.DomainSignedPolicyData{
					KeyId:     "dummyKeyID",
					Signature: "dummySig",
					SignedPolicyData: &util.SignedPolicyData{
						ZmsKeyId:     "dummyKeyID",
						ZmsSignature: "dummySig",
						Modified:     &rdl.Timestamp{Time: fastime.Now()},
						Expires:      &rdl.Timestamp{Time: fastime.Now().Add(time.Hour)},
						PolicyData: &util.PolicyData{
							Domain: "dummyDom",
							Policies: []*util.Policy{
								{
									Name:     "dummyDom:policy.dummyPol",
									Modified: &rdl.Timestamp{Time: fastime.Now()},
									Assertions: []*util.Assertion{
										{
											Role:     "dummyDom:role.dummyRole",
											Effect:   "ALLOW",
											Action:   "dummyAct",
											Resource: "dummyDom:dummyRes",
										},
									},
								},
							},
						},
					},
				},
			}
			fetchers[domain] = &fetcherMock{
				domainMock: func() string { return domain },
				fetchWithRetryMock: func(context.Context) (*SignedPolicy, error) {
					return sp, nil
				},
			}
			ctx := context.Background()

			// prepare test
			t.fields = fields{
				rolePolicies:          gache.New(),
				policyExpiredDuration: time.Hour,
				athenzDomains:         []string{domain},
				fetchers:              fetchers,
			}
			t.args = args{
				ctx: ctx,
			}

			// want
			wantAssertion, _ := NewAssertion("dummyAct", "dummyDom:dummyRes", "ALLOW")
			t.wantErr = ""
			t.wantRps = make(map[string]interface{})
			t.wantRps["dummyDom:role.dummyRole"] = []*Assertion{wantAssertion}
			return t
		}(),
		func() (t test) {
			t.name = "Update policy success with multiple athenz domains"

			// dummy values
			createSp := func(domain string) *SignedPolicy {
				return &SignedPolicy{
					util.DomainSignedPolicyData{
						KeyId:     "dummyKeyID",
						Signature: "dummySig",
						SignedPolicyData: &util.SignedPolicyData{
							ZmsKeyId:     "dummyKeyID",
							ZmsSignature: "dummySig",
							Modified:     &rdl.Timestamp{Time: fastime.Now()},
							Expires:      &rdl.Timestamp{Time: fastime.Now().Add(time.Hour)},
							PolicyData: &util.PolicyData{
								Domain: domain,
								Policies: []*util.Policy{
									{
										Name:     fmt.Sprintf("%s:policy.dummyPol", domain),
										Modified: &rdl.Timestamp{Time: fastime.Now()},
										Assertions: []*util.Assertion{
											{
												Role:     fmt.Sprintf("%s:role.dummyRole", domain),
												Effect:   "ALLOW",
												Action:   "dummyAct",
												Resource: fmt.Sprintf("%s:dummyRes", domain),
											},
										},
									},
								},
							},
						},
					},
				}
			}
			domains := make([]string, 1000)
			fetchers := make(map[string]Fetcher, 1000)
			for i := 0; i < 1000; i++ {
				d := fmt.Sprintf("dummyDom%d", i)
				domains[i] = d
				fetchers[d] = &fetcherMock{
					domainMock: func() string { return d },
					fetchWithRetryMock: func(context.Context) (*SignedPolicy, error) {
						return createSp(d), nil
					},
				}
			}
			ctx := context.Background()

			// prepare test
			t.fields = fields{
				rolePolicies:          gache.New(),
				policyExpiredDuration: time.Hour,
				athenzDomains:         domains,
				fetchers:              fetchers,
			}
			t.args = args{
				ctx: ctx,
			}

			// want
			t.wantErr = ""
			t.wantRps = make(map[string]interface{}, 1000)
			for i := 0; i < 1000; i++ {
				d := fmt.Sprintf("dummyDom%d", i)
				key := fmt.Sprintf("%s:role.dummyRole", d)
				wantAssertion, _ := NewAssertion("dummyAct", fmt.Sprintf("%s:dummyRes", d), "ALLOW")
				t.wantRps[key] = []*Assertion{wantAssertion}
			}
			return t
		}(),
		func() (t test) {
			t.name = "Update error, context timeout, no partial update"

			// dummy values
			createSp := func(domain string) *SignedPolicy {
				return &SignedPolicy{
					util.DomainSignedPolicyData{
						KeyId:     "dummyKeyID",
						Signature: "dummySig",
						SignedPolicyData: &util.SignedPolicyData{
							ZmsKeyId:     "dummyKeyID",
							ZmsSignature: "dummySig",
							Modified:     &rdl.Timestamp{Time: fastime.Now()},
							Expires:      &rdl.Timestamp{Time: fastime.Now().Add(time.Hour)},
							PolicyData: &util.PolicyData{
								Domain: domain,
								Policies: []*util.Policy{
									{
										Name:     fmt.Sprintf("%s:policy.dummyPol", domain),
										Modified: &rdl.Timestamp{Time: fastime.Now()},
										Assertions: []*util.Assertion{
											{
												Role:     fmt.Sprintf("%s:role.dummyRole", domain),
												Effect:   "ALLOW",
												Action:   "dummyAct",
												Resource: fmt.Sprintf("%s:dummyRes", domain),
											},
										},
									},
								},
							},
						},
					},
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*500) // timeout should be long enough to enter Fetch()
			go func() {
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Hour):
					cancel()
				}
			}()
			domains := make([]string, 100)
			fetchers := make(map[string]Fetcher, 100)
			for i := 0; i < 100; i++ {
				d := fmt.Sprintf("discardDom%d", i)
				domains[i] = d
				fetchers[d] = &fetcherMock{
					domainMock: func() string { return d },
					fetchWithRetryMock: func(ctx context.Context) (*SignedPolicy, error) {
						if d == "discardDom"+"0" {
							// blocking
							<-ctx.Done()
							return nil, ctx.Err()
						}
						return createSp(d), nil
					},
				}
			}

			// prepare test
			t.fields = fields{
				rolePolicies:          gache.New(),
				policyExpiredDuration: time.Hour,
				athenzDomains:         domains,
				fetchers:              fetchers,
			}
			t.args = args{
				ctx: ctx,
			}

			// want
			t.wantErr = "fetch policy fail: " + context.DeadlineExceeded.Error()
			t.wantRps = make(map[string]interface{})
			return t
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
				athenzURL:             tt.fields.athenzURL,
				athenzDomains:         tt.fields.athenzDomains,
				client:                tt.fields.client,
				fetchers:              tt.fields.fetchers,
			}
			err := p.Update(tt.args.ctx)
			if (err == nil && tt.wantErr != "") || (err != nil && err.Error() != tt.wantErr) {
				t.Errorf("policyd.Update() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			gotRps := p.GetPolicyCache(context.Background())
			if !cmp.Equal(gotRps, tt.wantRps, cmpopts.IgnoreFields(Assertion{}, "Reg")) {
				t.Errorf("policyd.Update() rolePolicies = %v, want %v", gotRps, tt.wantRps)
				t.Errorf("policyd.Update() rolePolicies diff = %s", cmp.Diff(gotRps, tt.wantRps, cmpopts.IgnoreFields(Assertion{}, "Reg")))
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
		{
			name: "check policy, context cancel",
			fields: fields{
				rolePolicies: gache.New(),
			},
			args: args{
				ctx: func() context.Context {
					ctx, cancel := context.WithCancel(context.Background())
					cancel()
					return ctx
				}(),
				domain:   "dummyDom",
				roles:    []string{"dummyRole"},
				action:   "dummyAct",
				resource: "dummyRes",
			},
			want: context.Canceled,
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

func Test_policyd_CheckPolicy_goroutine(t *testing.T) {
	type fields struct {
		expireMargin     time.Duration
		rolePolicies     gache.Gache
		refreshDuration  time.Duration
		errRetryInterval time.Duration
		pkp              pubkey.Provider
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
			name: "check policy: control test",
			fields: fields{
				rolePolicies: func() gache.Gache {
					g := gache.New()
					g.Set("domain:role.role1", []*Assertion{
						func() *Assertion {
							a, _ := NewAssertion("action", "domain:resource", "deny")
							return a
						}(),
					})
					return g
				}(),
			},
			args: args{
				ctx:      context.Background(),
				domain:   "domain",
				roles:    []string{"role1", "role2", "role3", "role4"},
				action:   "action",
				resource: "resource",
			},
			want: errors.New("policy deny: Access Check was explicitly denied"),
		},
		{
			name: "check policy multiple deny deadlock",
			fields: fields{
				rolePolicies: func() gache.Gache {
					g := gache.New()
					g.Set("domain:role.role1", []*Assertion{
						func() *Assertion {
							a, _ := NewAssertion("action", "domain:resource", "deny")
							return a
						}(),
					})
					g.Set("domain:role.role2", []*Assertion{
						func() *Assertion {
							a, _ := NewAssertion("action", "domain:resource", "deny")
							return a
						}(),
					})
					g.Set("domain:role.role3", []*Assertion{
						func() *Assertion {
							a, _ := NewAssertion("action", "domain:resource", "deny")
							return a
						}(),
					})
					g.Set("domain:role.role4", []*Assertion{
						func() *Assertion {
							a, _ := NewAssertion("action", "domain:resource", "deny")
							return a
						}(),
					})
					return g
				}(),
			},
			args: args{
				ctx:      context.Background(),
				domain:   "domain",
				roles:    []string{"role1", "role2", "role3", "role4"},
				action:   "action",
				resource: "resource",
			},
			want: errors.New("policy deny: Access Check was explicitly denied"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &policyd{
				expireMargin:     tt.fields.expireMargin,
				rolePolicies:     tt.fields.rolePolicies,
				refreshDuration:  tt.fields.refreshDuration,
				errRetryInterval: tt.fields.errRetryInterval,
				pkp:              tt.fields.pkp,
				athenzURL:        tt.fields.athenzURL,
				athenzDomains:    tt.fields.athenzDomains,
				client:           tt.fields.client,
			}

			b := make([]byte, 10240)
			lenStart := runtime.Stack(b, true)
			oldStack := string(b[:lenStart])
			// t.Log(oldStack)
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

			// check runtime stack for go routine leak
			time.Sleep(time.Millisecond * 500) // wait for some background process to cleanup
			lenEnd := runtime.Stack(b, true)
			// t.Log(string(b[:lenEnd]))
			if math.Abs(float64(lenStart-lenEnd)) > 10 { // to tolerate fastime package goroutine status change, leaking will cause much larger stack length difference
				t.Errorf("go routine leak:\n%v", cmp.Diff(oldStack, string(b[:lenEnd])))
			}
		})
	}
}

func Test_fetchAndCachePolicy(t *testing.T) {
	type args struct {
		ctx context.Context
		g   gache.Gache
		f   Fetcher
	}
	type test struct {
		name    string
		args    args
		wantErr string
		wantRps map[string]interface{}
	}
	createDummySp := func() *SignedPolicy {
		return &SignedPolicy{
			util.DomainSignedPolicyData{
				KeyId:     "dummyKeyID",
				Signature: "dummySig",
				SignedPolicyData: &util.SignedPolicyData{
					ZmsKeyId:     "dummyKeyID",
					ZmsSignature: "dummySig",
					Modified:     &rdl.Timestamp{Time: fastime.Now()},
					Expires:      &rdl.Timestamp{Time: fastime.Now().Add(time.Hour)},
					PolicyData: &util.PolicyData{
						Domain: "dummyDom",
						Policies: []*util.Policy{
							{
								Name:     "dummyDom:policy.dummyPol",
								Modified: &rdl.Timestamp{Time: fastime.Now()},
								Assertions: []*util.Assertion{
									{
										Role:     "dummyDom:role.dummyRole",
										Effect:   "ALLOW",
										Action:   "dummyAct",
										Resource: "dummyDom:dummyRes",
									},
								},
							},
						},
					},
				},
			},
		}
	}
	tests := []test{
		func() (t test) {
			t.name = "fetch success, update cache"

			// dummy values
			domain := "dummyDom"
			sp := createDummySp()
			fetcher := &fetcherMock{
				domainMock: func() string { return domain },
				fetchWithRetryMock: func(context.Context) (*SignedPolicy, error) {
					return sp, nil
				},
			}
			ctx := context.Background()

			// prepare test
			t.args = args{
				ctx: ctx,
				g:   gache.New(),
				f:   fetcher,
			}

			// want
			wantAssertion, _ := NewAssertion("dummyAct", "dummyDom:dummyRes", "ALLOW")
			t.wantErr = ""
			t.wantRps = make(map[string]interface{})
			t.wantRps["dummyDom:role.dummyRole"] = []*Assertion{wantAssertion}
			return t
		}(),
		func() (t test) {
			t.name = "fetch failed, no cache, error"

			// dummy values
			domain := "dummyDom"
			fetcher := &fetcherMock{
				domainMock: func() string { return domain },
				fetchWithRetryMock: func(context.Context) (*SignedPolicy, error) {
					return nil, errors.New("no cache")
				},
			}
			ctx := context.Background()

			// prepare test
			t.args = args{
				ctx: ctx,
				g:   gache.New(),
				f:   fetcher,
			}

			// want
			t.wantErr = "fetch policy fail: no cache"
			t.wantRps = make(map[string]interface{})
			return t
		}(),
		func() (t test) {
			t.name = "fetch failed, but with cached policy, update cache"

			// dummy values
			domain := "dummyDom"
			sp := createDummySp()
			fetcher := &fetcherMock{
				domainMock: func() string { return domain },
				fetchWithRetryMock: func(context.Context) (*SignedPolicy, error) {
					return sp, errors.New("something wrong, return cache")
				},
			}
			ctx := context.Background()

			// prepare test
			t.args = args{
				ctx: ctx,
				g:   gache.New(),
				f:   fetcher,
			}

			// want
			wantAssertion, _ := NewAssertion("dummyAct", "dummyDom:dummyRes", "ALLOW")
			t.wantErr = ""
			t.wantRps = make(map[string]interface{})
			t.wantRps["dummyDom:role.dummyRole"] = []*Assertion{wantAssertion}
			return t
		}(),
		func() (t test) {
			t.name = "simplifyAndCache failed, error"

			// dummy values
			domain := "dummyDom"
			sp := createDummySp()
			fetcher := &fetcherMock{
				domainMock: func() string { return domain },
				fetchWithRetryMock: func(context.Context) (*SignedPolicy, error) {
					return sp, nil
				},
			}
			ctx := context.Background()

			// prepare test
			sp.SignedPolicyData.PolicyData.Policies[0].Assertions[0].Resource = "invalid-resource"
			t.args = args{
				ctx: ctx,
				g:   gache.New(),
				f:   fetcher,
			}

			// want
			t.wantErr = "simplify and cache policy fail: assertion format not correct: Access denied due to invalid/empty policy resources"
			t.wantRps = make(map[string]interface{})
			return t
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := fetchAndCachePolicy(tt.args.ctx, tt.args.g, tt.args.f)
			if (err == nil && tt.wantErr != "") || (err != nil && err.Error() != tt.wantErr) {
				t.Errorf("fetchAndCachePolicy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			gotRps := tt.args.g.ToRawMap(context.Background())
			if !cmp.Equal(gotRps, tt.wantRps, cmpopts.IgnoreFields(Assertion{}, "Reg")) {
				t.Errorf("fetchAndCachePolicy() g = %v, want %v", gotRps, tt.wantRps)
				t.Errorf("fetchAndCachePolicy() g diff = %s", cmp.Diff(gotRps, tt.wantRps, cmpopts.IgnoreFields(Assertion{}, "Reg")))
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
			expires := fastime.Now().Add(time.Hour).UTC()
			return test{
				name: "cache success with data",
				args: args{
					ctx: context.Background(),
					rp:  rp,
					sp: &SignedPolicy{
						util.DomainSignedPolicyData{
							SignedPolicyData: &util.SignedPolicyData{
								Expires: &rdl.Timestamp{
									Time: expires,
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

					gotRp1, gotExpire1, ok := rp.GetWithExpire("dummyDom:role.dummyRole")
					if !ok {
						return errors.New("cannot simplify and cache data")
					}
					if math.Abs(time.Unix(0, gotExpire1).Sub(expires).Seconds()) > time.Second.Seconds()*3 {
						return errors.New("cache expiry not match with policy expires")
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

					gotRp2, gotExpire2, ok := rp.GetWithExpire("dummyDom2:role.dummyRole2")
					if !ok {
						return errors.New("cannot simplify and cache data")
					}
					if math.Abs(time.Unix(0, gotExpire2).Sub(expires).Seconds()) > time.Second.Seconds()*3 {
						return errors.New("cache expiry not match with policy expires")
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
			ctx, cancel := context.WithDeadline(context.Background(), fastime.Now().Add(time.Nanosecond*5))
			return test{
				name: "test context done",
				args: args{
					ctx: ctx,
					rp:  rp,
					sp: &SignedPolicy{
						util.DomainSignedPolicyData{
							SignedPolicyData: &util.SignedPolicyData{
								Expires: &rdl.Timestamp{
									Time: fastime.Now().Add(time.Hour * 99999).UTC(),
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
									Time: fastime.Now().Add(time.Hour * 99999).UTC(),
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
					sp: &SignedPolicy{
						util.DomainSignedPolicyData{
							SignedPolicyData: &util.SignedPolicyData{
								Expires: &rdl.Timestamp{
									Time: fastime.Now().Add(time.Hour).UTC(),
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
									Time: fastime.Now().Add(time.Hour).UTC(),
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
										fastime.Now().Add(time.Hour).UTC(),
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
									Time: fastime.Now().Add(time.Hour).UTC(),
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
									Time: fastime.Now().Add(time.Hour).UTC(),
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
