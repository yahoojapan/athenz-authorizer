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
	"github.com/kpango/fastime"
	"github.com/kpango/gache"
	"github.com/pkg/errors"
	authcore "github.com/yahoo/athenz/libs/go/zmssvctoken"
	"github.com/yahoo/athenz/utils/zpe-updater/util"
	"github.com/yahoojapan/athenz-authorizer/pubkey"
)

func Test_policyd_fetchPolicy_expiry(t *testing.T) {
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
			domain := "dummyDomain"
			handler := http.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotModified)
			}))
			srv := httptest.NewTLSServer(handler)
			cachedSp := &SignedPolicy{
				util.DomainSignedPolicyData{
					SignedPolicyData: &util.SignedPolicyData{
						ZmsKeyId: "cached-policy",
						Expires: &rdl.Timestamp{
							Time: fastime.Now().Add(-1 * time.Hour).UTC(),
						},
					},
				},
			}
			wantSp := cachedSp

			// old etag cache
			etagCac := gache.New()
			etagCac.Set(domain, &etagCache{
				etag: "\"dummyOldEtag\"",
				sp:   cachedSp,
			})

			return test{
				name: "test policy already expired (304), no expiry checking, return expired policy",
				fields: fields{
					athenzURL:             strings.Replace(srv.URL, "https://", "", 1),
					policyExpiredDuration: time.Minute * 30,
					etagCache:             etagCac,
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
					domain: domain,
				},
				checkFunc: func(p *policyd, sp *SignedPolicy, upd bool, err error) error {
					// check return values
					if err != nil {
						return err
					}
					if !reflect.DeepEqual(sp, wantSp) {
						return fmt.Errorf("SignedPolicy got: %+v, want: %+v", *sp.DomainSignedPolicyData.SignedPolicyData, *wantSp.DomainSignedPolicyData.SignedPolicyData)
					}
					if upd != false {
						return errors.New("upd should be false")
					}
					if fastime.Now().Before(sp.SignedPolicyData.Expires.Time) {
						// strange behavior
						return errors.New("returned policy should be expired")
					}

					// check etag cache values
					etagCac, ok := p.etagCache.Get(domain)
					if !ok {
						return errors.New("etag cache should be found")
					}
					// check policy same
					gotCachedSp := etagCac.(*etagCache).sp
					if gotCachedSp != wantSp {
						return fmt.Errorf("etag cache SignedPolicy got: %+v, want: %+v", *gotCachedSp.DomainSignedPolicyData.SignedPolicyData, *wantSp.DomainSignedPolicyData.SignedPolicyData)
					}

					return nil
				},
			}
		}(),
		func() test {
			domain := "dummyDomain"
			handler := http.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("ETag", "\"dummyNewEtag\"")
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"signedPolicyData":{
					"zmsKeyId": "zmsKeyId-137"
				}}`))
			}))
			srv := httptest.NewTLSServer(handler)
			cachedSp := &SignedPolicy{
				util.DomainSignedPolicyData{
					SignedPolicyData: &util.SignedPolicyData{
						ZmsKeyId: "zmsKeyId-144",
					},
				},
			}
			wantSp := &SignedPolicy{
				util.DomainSignedPolicyData{
					SignedPolicyData: &util.SignedPolicyData{
						ZmsKeyId: "zmsKeyId-137",
					},
				},
			}

			// old etag cache, to confirm update
			etagCac := gache.New()
			etagCac.Set(domain, &etagCache{
				etag: "\"dummyOldEtag\"",
				sp:   cachedSp,
			})

			etagExpTime := 2 * time.Hour
			expireMargin := time.Hour

			return test{
				name: "test policy without expiry, skip expiry check, set etagCache with (etagExpTime - expireMargin)",
				fields: fields{
					athenzURL:             strings.Replace(srv.URL, "https://", "", 1),
					policyExpiredDuration: time.Minute * 30,
					etagCache:             etagCac,
					etagExpTime:           etagExpTime,
					expireMargin:          expireMargin,
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
					domain: domain,
				},
				checkFunc: func(p *policyd, sp *SignedPolicy, upd bool, err error) error {
					// check return values
					if err != nil {
						return err
					}
					if !reflect.DeepEqual(sp, wantSp) {
						return fmt.Errorf("SignedPolicy got: %+v, want: %+v", *sp.DomainSignedPolicyData.SignedPolicyData, *wantSp.DomainSignedPolicyData.SignedPolicyData)
					}
					if upd != true {
						return errors.New("upd should be true")
					}

					// check etag cache values
					etagCac, gotExpiry, ok := p.etagCache.GetWithExpire(domain)
					if !ok {
						return errors.New("etag cache should be found")
					}
					// check etag
					wantEtag := "\"dummyNewEtag\""
					gotEtag := etagCac.(*etagCache).etag
					if gotEtag != wantEtag {
						return fmt.Errorf("etag got: %v, want: %v", gotEtag, wantEtag)
					}
					// check policy equal
					gotCachedSp := etagCac.(*etagCache).sp
					if !reflect.DeepEqual(gotCachedSp, wantSp) {
						return fmt.Errorf("etag cache SignedPolicy got: %+v, want: %+v", *gotCachedSp.DomainSignedPolicyData.SignedPolicyData, *wantSp.DomainSignedPolicyData.SignedPolicyData)
					}
					// check cache expire time
					wantExpiry := fastime.Now().Add(etagExpTime).Add(-1 * expireMargin).UnixNano()
					if (wantExpiry - gotExpiry) > (time.Second * 3).Nanoseconds() {
						return fmt.Errorf("etag cache expiry got: %v, want: %v", gotExpiry, wantExpiry)

					}

					return nil
				},
			}
		}(),
		func() test {
			domain := "dummyDomain"
			handler := http.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("ETag", "\"dummyNewEtag\"")
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusOK)
				// only customized format works
				w.Write([]byte(`{"signedPolicyData":{
					"zmsKeyId": "zmsKeyId-235",
					"expires":"2099-12-31"
				}}`))
			}))
			srv := httptest.NewTLSServer(handler)
			cachedSp := &SignedPolicy{
				util.DomainSignedPolicyData{
					SignedPolicyData: &util.SignedPolicyData{
						ZmsKeyId: "zmsKeyId-243",
					},
				},
			}

			// old etag cache, to confirm delete
			etagCac := gache.New()
			etagCac.Set(domain, &etagCache{
				etag: "\"dummyOldEtag\"",
				sp:   cachedSp,
			})

			return test{
				name: "test policy with invalid expiry, expiry check fail, remove etagCache",
				fields: fields{
					athenzURL:             strings.Replace(srv.URL, "https://", "", 1),
					policyExpiredDuration: time.Minute * 30,
					etagCache:             etagCac,
					etagExpTime:           time.Hour,
					expireMargin:          time.Minute,
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
					domain: domain,
				},
				checkFunc: func(p *policyd, sp *SignedPolicy, upd bool, err error) error {
					// check return values
					wantError := "policy already expired"
					if err.Error() != wantError {
						return fmt.Errorf("err got: %v, want: %v", err.Error(), wantError)
					}
					if sp != nil {
						return errors.New("sp should be nil")
					}
					if upd != false {
						return errors.New("upd should be false")
					}

					// check etag cache empty
					_, ok := p.etagCache.Get(domain)
					if ok {
						return errors.New("etag cache should be not found")
					}

					return nil
				},
			}
		}(),
		func() test {
			domain := "dummyDomain"
			handler := http.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tByte, err := rdl.Timestamp{
					Time: fastime.Now().Add(-1 * time.Hour).UTC(),
				}.MarshalJSON()
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(err.Error()))
				} else {
					w.Header().Set("ETag", "\"dummyNewEtag\"")
					w.Header().Set("Content-Type", "application/json; charset=utf-8")
					w.WriteHeader(http.StatusOK)
					json := fmt.Sprintf(`{"signedPolicyData":{
						"zmsKeyId": "zmsKeyId-322",
						"expires": %v
					}}`, string(tByte))
					w.Write([]byte(json))
				}
			}))
			srv := httptest.NewTLSServer(handler)
			cachedSp := &SignedPolicy{
				util.DomainSignedPolicyData{
					SignedPolicyData: &util.SignedPolicyData{
						ZmsKeyId: "zmsKeyId-332",
					},
				},
			}

			// old etag cache, to confirm delete
			etagCac := gache.New()
			etagCac.Set(domain, &etagCache{
				etag: "\"dummyOldEtag\"",
				sp:   cachedSp,
			})

			return test{
				name: "test policy already expired, expiry check fail, remove etagCache",
				fields: fields{
					athenzURL:             strings.Replace(srv.URL, "https://", "", 1),
					policyExpiredDuration: time.Minute * 30,
					etagCache:             etagCac,
					etagExpTime:           time.Hour,
					expireMargin:          time.Minute,
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
					domain: domain,
				},
				checkFunc: func(p *policyd, sp *SignedPolicy, upd bool, err error) error {
					// check return values
					wantError := "policy already expired"
					if err.Error() != wantError {
						return fmt.Errorf("err got: %v, want: %v", err.Error(), wantError)
					}
					if sp != nil {
						return errors.New("sp should be nil")
					}
					if upd != false {
						return errors.New("upd should be false")
					}

					// check etag cache empty
					_, ok := p.etagCache.Get(domain)
					if ok {
						return errors.New("etag cache should be not found")
					}

					return nil
				},
			}
		}(),
		func() test {
			domain := "dummyDomain"
			handler := http.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tByte, err := rdl.Timestamp{
					Time: fastime.Now().Add(1 * time.Hour).UTC(),
				}.MarshalJSON()
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(err.Error()))
				} else {
					w.Header().Set("ETag", "\"dummyNewEtag\"")
					w.Header().Set("Content-Type", "application/json; charset=utf-8")
					w.WriteHeader(http.StatusOK)
					json := fmt.Sprintf(`{"signedPolicyData":{
						"zmsKeyId": "zmsKeyId-403",
						"expires": %v
					}}`, string(tByte))
					w.Write([]byte(json))
				}
			}))
			srv := httptest.NewTLSServer(handler)
			cachedSp := &SignedPolicy{
				util.DomainSignedPolicyData{
					SignedPolicyData: &util.SignedPolicyData{
						ZmsKeyId: "zmsKeyId-414",
					},
				},
			}

			// old etag cache, to confirm delete
			etagCac := gache.New()
			etagCac.Set(domain, &etagCache{
				etag: "\"dummyOldEtag\"",
				sp:   cachedSp,
			})

			return test{
				name: "test policy expire by expireMargin, expiry check fail, remove etagCache",
				fields: fields{
					athenzURL:             strings.Replace(srv.URL, "https://", "", 1),
					policyExpiredDuration: time.Minute * 30,
					etagCache:             etagCac,
					etagExpTime:           time.Hour,
					expireMargin:          2 * time.Hour,
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
					domain: domain,
				},
				checkFunc: func(p *policyd, sp *SignedPolicy, upd bool, err error) error {
					// check return values
					wantError := "policy already expired"
					if err.Error() != wantError {
						return fmt.Errorf("err got: %v, want: %v", err.Error(), wantError)
					}
					if sp != nil {
						return errors.New("sp should be nil")
					}
					if upd != false {
						return errors.New("upd should be false")
					}

					// check etag cache empty
					_, ok := p.etagCache.Get(domain)
					if ok {
						return errors.New("etag cache should be not found")
					}

					return nil
				},
			}
		}(),
		func() test {
			domain := "dummyDomain"
			policyExpires := rdl.Timestamp{
				Time: fastime.Now().Add(1 * time.Hour).Truncate(time.Millisecond).UTC(),
			}
			expireMargin := 30 * time.Minute
			handler := http.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tByte, err := policyExpires.MarshalJSON()
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(err.Error()))
				} else {
					w.Header().Set("ETag", "\"dummyNewEtag\"")
					w.Header().Set("Content-Type", "application/json; charset=utf-8")
					w.WriteHeader(http.StatusOK)
					json := fmt.Sprintf(`{"signedPolicyData":{
						"zmsKeyId": "zmsKeyId-482",
						"expires": %v
					}}`, string(tByte))
					w.Write([]byte(json))
				}
			}))
			srv := httptest.NewTLSServer(handler)
			cachedSp := &SignedPolicy{
				util.DomainSignedPolicyData{
					SignedPolicyData: &util.SignedPolicyData{
						ZmsKeyId: "zmsKeyId-492",
					},
				},
			}
			wantSp := &SignedPolicy{
				util.DomainSignedPolicyData{
					SignedPolicyData: &util.SignedPolicyData{
						ZmsKeyId: "zmsKeyId-482",
						Expires: &policyExpires,
					},
				},
			}

			// old etag cache, to confirm update
			etagCac := gache.New()
			etagCac.Set(domain, &etagCache{
				etag: "\"dummyOldEtag\"",
				sp:   cachedSp,
			})

			return test{
				name: "test valid policy (200), set etagCache with (policyExpires - expireMargin)",
				fields: fields{
					athenzURL:             strings.Replace(srv.URL, "https://", "", 1),
					policyExpiredDuration: time.Minute * 30,
					etagCache:             etagCac,
					etagExpTime:           time.Hour,
					expireMargin:          expireMargin,
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
					domain: domain,
				},
				checkFunc: func(p *policyd, sp *SignedPolicy, upd bool, err error) error {
					// check return values
					if err != nil {
						return err
					}
					if !reflect.DeepEqual(sp.DomainSignedPolicyData.SignedPolicyData, wantSp.DomainSignedPolicyData.SignedPolicyData) {
						return fmt.Errorf("SignedPolicy got: %+v, want: %+v", *sp.DomainSignedPolicyData.SignedPolicyData, *wantSp.DomainSignedPolicyData.SignedPolicyData)
					}
					if upd != true {
						return errors.New("upd should be true")
					}

					// check etag cache values
					etagCac, gotExpiry, ok := p.etagCache.GetWithExpire(domain)
					if !ok {
						return errors.New("etag cache should be found")
					}
					// check etag
					wantEtag := "\"dummyNewEtag\""
					gotEtag := etagCac.(*etagCache).etag
					if gotEtag != wantEtag {
						return fmt.Errorf("etag got: %v, want: %v", gotEtag, wantEtag)
					}
					// check policy equal
					gotCachedSp := etagCac.(*etagCache).sp
					if !reflect.DeepEqual(gotCachedSp, wantSp) {
						return fmt.Errorf("etag cache SignedPolicy got: %+v, want: %+v", *gotCachedSp.DomainSignedPolicyData.SignedPolicyData, *wantSp.DomainSignedPolicyData.SignedPolicyData)
					}
					// // check cache expire time
					wantExpiry := wantSp.DomainSignedPolicyData.SignedPolicyData.Expires.UnixNano()
					if (gotExpiry - wantExpiry) > (time.Second * 3).Nanoseconds() {
						return fmt.Errorf("etag cache expiry got: %v, want: %v", gotExpiry, wantExpiry)
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
