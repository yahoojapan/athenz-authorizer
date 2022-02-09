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
package pubkey

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	authcore "github.com/AthenZ/athenz/libs/go/zmssvctoken"
	cmp "github.com/google/go-cmp/cmp"
	"github.com/kpango/gache"
	"github.com/pkg/errors"
)

func TestNew(t *testing.T) {
	type args struct {
		opts []Option
	}
	type test struct {
		name      string
		args      args
		checkFunc func(Daemon, error) error
	}
	tests := []test{
		{
			name: "new athenz pubkeyd success",
			args: args{
				opts: []Option{},
			},
			checkFunc: func(got Daemon, err error) error {
				if err != nil {
					return err
				}
				if got.(*pubkeyd).sysAuthDomain != "sys.auth" {
					return errors.New("cannot set default options")
				}
				return nil
			},
		},
		{
			name: "new athenz pubkeyd success with options",
			args: args{
				opts: []Option{
					WithSysAuthDomain("dummySysDomain"),
					WithAthenzURL("dummyURL"),
				},
			},
			checkFunc: func(got Daemon, err error) error {
				if err != nil {
					return err
				}
				if got.(*pubkeyd).sysAuthDomain != "dummySysDomain" || got.(*pubkeyd).athenzURL != "dummyURL" {
					return errors.New("cannot set optional params")
				}
				return nil
			},
		},
		{
			name: "new athenz pubkeyd error with invalid options",
			args: args{
				opts: []Option{
					WithSysAuthDomain("dummySysDomain"),
					WithAthenzURL("dummyURL"),
					WithETagExpiry("invalid"),
				},
			},
			checkFunc: func(got Daemon, err error) error {
				if got != nil {
					return errors.New("get invalid Daemon")
				}
				if err.Error() != "error create pubkeyd: invalid ETag expiry time: time: invalid duration invalid" {
					return errors.Wrap(err, "unexpected error")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.args.opts...)
			err = tt.checkFunc(got, err)
			if err != nil {
				t.Errorf("New() = %v", err)
			}
		})
	}
}

func Test_pubkeyd_getPubKey(t *testing.T) {
	c := &pubkeyd{
		confCache: &AthenzConfig{
			ZMSPubKeys: new(sync.Map),
			ZTSPubKeys: new(sync.Map),
		},
	}
	zmsVer := &VerifierMock{}
	ztsVer := &VerifierMock{}
	c.confCache.ZMSPubKeys.Store("0", zmsVer)
	c.confCache.ZTSPubKeys.Store("0", ztsVer)
	type args struct {
		env   AthenzEnv
		keyID string
	}
	type test struct {
		name string
		args args
		want authcore.Verifier
	}
	tests := []test{
		{
			name: "get success",
			args: args{
				env:   "zts",
				keyID: "0",
			},
			want: ztsVer,
		},
		{
			name: "not found zms",
			args: args{
				env:   "zms",
				keyID: "1",
			},
			want: nil,
		},
		{
			name: "not found zts",
			args: args{
				env:   "zts",
				keyID: "1",
			},
			want: nil,
		},
		{
			name: "invalid env",
			args: args{
				env:   "dummy",
				keyID: "0",
			},
			want: zmsVer,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := c.getPubKey(tt.args.env, tt.args.keyID)
			if got != tt.want {
				t.Errorf("getPubKey() = expect: %v	result: %v", tt.want, got)
			}
		})
	}
}

func Test_pubkeyd_fetchPubKeyEntries(t *testing.T) {
	type fields struct {
		refreshPeriod   time.Duration
		retryDelay      time.Duration
		eTagCache       gache.Gache
		eTagPurgePeriod time.Duration
		eTagExpiry      time.Duration
		athenzURL       string
		sysAuthDomain   string
		client          *http.Client
		confCache       *AthenzConfig
	}
	type args struct {
		ctx context.Context
		env AthenzEnv
	}
	type test struct {
		name      string
		fields    fields
		args      args
		checkFunc func(c *pubkeyd, sac *SysAuthConfig, upd bool, err error) error
	}
	tests := []test{
		func() test {
			handler := http.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Add("ETag", "dummyETag")
				_, err := w.Write([]byte(`{"name":"dummyDom.dummyEnv","publicKeys":[{"key":"dummyKey","id":"dummyID"}],"modified":"2017-01-23T02:20:09.331Z"}`))
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			srv := httptest.NewTLSServer(handler)

			return test{
				name: "test fetch success",
				fields: fields{
					athenzURL:     strings.Replace(srv.URL, "https://", "", 1),
					sysAuthDomain: "dummyDom",
					eTagCache:     gache.New(),
					eTagExpiry:    time.Minute,
					client:        srv.Client(),
					confCache: &AthenzConfig{
						ZMSPubKeys: new(sync.Map),
						ZTSPubKeys: new(sync.Map),
					},
				},
				args: args{
					ctx: context.Background(),
					env: "dummyEnv",
				},
				checkFunc: func(c *pubkeyd, sac *SysAuthConfig, upd bool, err error) error {
					if err != nil {
						return err
					}

					_, ok := c.eTagCache.Get("dummyDomain")
					if ok {
						return errors.New("invalid ETag was set")
					}

					want := &SysAuthConfig{
						Modified: "2017-01-23T02:20:09.331Z",
						Name:     "dummyDom.dummyEnv",
						PublicKeys: []*PublicKey{
							{
								ID:  "dummyID",
								Key: "dummyKey",
							},
						},
					}

					if !cmp.Equal(sac, want) {
						return errors.Errorf("not match, got: %v, want: %v", sac, want)
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
				if r.Header.Get("If-None-Match") == "dummyOldETag" {
					w.WriteHeader(http.StatusNotModified)
				} else {
					w.Header().Add("ETag", "dummyNewETag")
					w.WriteHeader(http.StatusOK)
				}
			}))
			srv := httptest.NewTLSServer(handler)

			ec := gache.New()
			ec.Set("dummyEnv", &confCache{
				eTag: "dummyOldETag",
				sac: &SysAuthConfig{
					Modified: "2017-01-23T02:20:09.331Z",
					Name:     "dummyDom.dummyEnv",
					PublicKeys: []*PublicKey{
						{
							ID:  "dummyID",
							Key: "dummyKey",
						},
					},
				},
			})

			return test{
				name: "test ETag exists but not modified",
				fields: fields{
					athenzURL:     strings.Replace(srv.URL, "https://", "", 1),
					sysAuthDomain: "dummyDom",
					eTagCache:     ec,
					eTagExpiry:    time.Minute,
					client:        srv.Client(),
					confCache: &AthenzConfig{
						ZMSPubKeys: new(sync.Map),
						ZTSPubKeys: new(sync.Map),
					},
				},
				args: args{
					ctx: context.Background(),
					env: "dummyEnv",
				},
				checkFunc: func(c *pubkeyd, sac *SysAuthConfig, upd bool, err error) error {
					if err != nil {
						return err
					}

					eTag, ok := c.eTagCache.Get("dummyEnv")
					if !ok {
						return errors.New("cannot use ETag cache")
					}

					want := eTag.(*confCache).sac
					if !cmp.Equal(sac, want) {
						return errors.Errorf("not match, got: %v, want: %v", sac, want)
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
				if r.Header.Get("If-None-Match") == "dummyNewETag" {
					w.WriteHeader(http.StatusNotModified)
					return
				}
				w.Header().Add("ETag", "dummyNewETag")
				w.WriteHeader(http.StatusOK)
				_, err := w.Write([]byte(`{"name":"dummyDom.dummyEnv","publicKeys":[{"key":"dummyNewKey","id":"dummyNewID"}],"modified":"2999-01-23T02:20:09.331Z"}`))
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
			}))
			srv := httptest.NewTLSServer(handler)

			ec := gache.New()
			ec.Set("dummyEnv", &confCache{
				eTag: "dummyOldETag",
				sac:  &SysAuthConfig{},
			})

			return test{
				name: "test ETag exists but modified",
				fields: fields{
					athenzURL:     strings.Replace(srv.URL, "https://", "", 1),
					sysAuthDomain: "dummyDom",
					eTagCache:     ec,
					eTagExpiry:    time.Minute,
					client:        srv.Client(),
					confCache: &AthenzConfig{
						ZMSPubKeys: new(sync.Map),
						ZTSPubKeys: new(sync.Map),
					},
				},
				args: args{
					ctx: context.Background(),
					env: "dummyEnv",
				},
				checkFunc: func(c *pubkeyd, sac *SysAuthConfig, upd bool, err error) error {
					if err != nil {
						return err
					}

					_, ok := c.eTagCache.Get("dummyEnv")
					if !ok {
						return errors.New("cannot use ETag cache")
					}
					want := &SysAuthConfig{
						Modified: "2999-01-23T02:20:09.331Z",
						Name:     "dummyDom.dummyEnv",
						PublicKeys: []*PublicKey{
							{
								ID:  "dummyNewID",
								Key: "dummyNewKey",
							},
						},
					}
					if !cmp.Equal(sac, want) {
						return errors.Errorf("not match, got: %v, want: %v", sac, want)
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
				w.WriteHeader(http.StatusInternalServerError)
			}))
			srv := httptest.NewTLSServer(handler)

			return test{
				name: "test not statusOK",
				fields: fields{
					athenzURL:     strings.Replace(srv.URL, "https://", "", 1),
					sysAuthDomain: "dummyDom",
					eTagCache:     gache.New(),
					eTagExpiry:    time.Minute,
					client:        srv.Client(),
					confCache: &AthenzConfig{
						ZMSPubKeys: new(sync.Map),
						ZTSPubKeys: new(sync.Map),
					},
				},
				args: args{
					ctx: context.Background(),
					env: "dummyEnv",
				},
				checkFunc: func(c *pubkeyd, sac *SysAuthConfig, upd bool, err error) error {
					wantErr := "http return status not OK: Fetch athenz pubkey error"
					if err != nil {
						if err.Error() == wantErr {
							return nil
						}
						return errors.Errorf("unexpected error. want = %s, got = %s", wantErr, err.Error())
					}
					return errors.Errorf("http status is not OK, but fetch success")
				},
			}
		}(),
		func() test {
			handler := http.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			srv := httptest.NewTLSServer(handler)

			return test{
				name: "test cannot create get pubkey request",
				fields: fields{
					athenzURL:     " ",
					sysAuthDomain: "dummyDom",
					eTagCache:     gache.New(),
					eTagExpiry:    time.Minute,
					client:        srv.Client(),
					confCache: &AthenzConfig{
						ZMSPubKeys: new(sync.Map),
						ZTSPubKeys: new(sync.Map),
					},
				},
				args: args{
					ctx: context.Background(),
					env: "dummyEnv",
				},
				checkFunc: func(c *pubkeyd, sac *SysAuthConfig, upd bool, err error) error {
					wantErr := `error creating get pubkey request: parse "https:// /domain/dummyDom/service/dummyEnv": invalid character " " in host name`
					if err != nil {
						if err.Error() == wantErr {
							return nil
						}
						return errors.Errorf("unexpected error. want = %s, got = %s", wantErr, err.Error())
					}
					return errors.Errorf("http status is not OK, but fetch success")
				},
			}
		}(),
		func() test {
			handler := http.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			srv := httptest.NewTLSServer(handler)

			return test{
				name: "test fetch invalid json",
				fields: fields{
					athenzURL:     strings.Replace(srv.URL, "https://", "", 1),
					sysAuthDomain: "dummyDom",
					eTagCache:     gache.New(),
					eTagExpiry:    time.Minute,
					client:        srv.Client(),
					confCache: &AthenzConfig{
						ZMSPubKeys: new(sync.Map),
						ZTSPubKeys: new(sync.Map),
					},
				},
				args: args{
					ctx: context.Background(),
					env: "dummyEnv",
				},
				checkFunc: func(c *pubkeyd, sac *SysAuthConfig, upd bool, err error) error {
					wantErr := "json format not correct: EOF"
					if err != nil {
						if err.Error() == wantErr {
							return nil
						}
						return errors.Errorf("unexpected error. want = %s, got = %s", wantErr, err.Error())
					}
					return errors.Errorf("http status is not OK, but fetch success")
				},
			}
		}(),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &pubkeyd{
				refreshPeriod:   tt.fields.refreshPeriod,
				retryDelay:      tt.fields.retryDelay,
				eTagCache:       tt.fields.eTagCache,
				eTagPurgePeriod: tt.fields.eTagPurgePeriod,
				eTagExpiry:      tt.fields.eTagExpiry,
				athenzURL:       tt.fields.athenzURL,
				sysAuthDomain:   tt.fields.sysAuthDomain,
				client:          tt.fields.client,
				confCache:       tt.fields.confCache,
			}
			got, got1, err := c.fetchPubKeyEntries(tt.args.ctx, tt.args.env)

			if err := tt.checkFunc(c, got, got1, err); err != nil {
				t.Errorf("c.fetchPubKeyEntries() error = %v", err)
			}
		})
	}
}

func Test_pubkeyd_GetProvider(t *testing.T) {
	c := &pubkeyd{
		confCache: &AthenzConfig{},
	}
	type test struct {
		name string
		want string
	}
	tests := []test{
		{
			name: "get success",
			want: "pubkey.Provider",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := c.GetProvider()
			if fmt.Sprint(reflect.TypeOf(got)) != tt.want {
				t.Errorf("c.GetProvider() error")
			}
		})
	}
}

func Test_pubkeyd_Update(t *testing.T) {
	type fields struct {
		refreshPeriod   time.Duration
		retryDelay      time.Duration
		eTagCache       gache.Gache
		eTagPurgePeriod time.Duration
		eTagExpiry      time.Duration
		athenzURL       string
		sysAuthDomain   string
		client          *http.Client
		confCache       *AthenzConfig
	}
	type args struct {
		ctx context.Context
	}
	type test struct {
		name      string
		fields    fields
		args      args
		checkFunc func(*pubkeyd, error) error
	}
	tests := []test{
		func() test {
			handler := http.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/domain/dummyDom/service/zms" {
					w.Header().Add("ETag", "dummyETag")
					_, err := w.Write([]byte(`{"name":"dummyDom.zms","publicKeys":[{"key":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FEVTU3VEVoWW5xUkRNM0R2UUM4ajNQSU1FeAp1M3JtYW9QakV6SnlRWTFrVm42MEE2cXJKTDJ1N3N2NHNTa1V5NjdJSUlhQ1VXNVp4aTRXUEdyazAvQm9oMDlGCkJWL1ZML0dMMTB6UmFvcDJXT3ZXRTlpSWNzKzJOK2pWTk1ycVhxZUNENFphK2dHdGdLTU5SMldiRlQvQlcra0wKUGlGeGg0U0NsVkZrdmI4Mm93SURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQ--","id":"0"},{"key":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FEVTU3VEVoWW5xUkRNM0R2UUM4ajNQSU1FeAp1M3JtYW9QakV6SnlRWTFrVm42MEE2cXJKTDJ1N3N2NHNTa1V5NjdJSUlhQ1VXNVp4aTRXUEdyazAvQm9oMDlGCkJWL1ZML0dMMTB6UmFvcDJXT3ZXRTlpSWNzKzJOK2pWTk1ycVhxZUNENFphK2dHdGdLTU5SMldiRlQvQlcra0wKUGlGeGg0U0NsVkZrdmI4Mm93SURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQ--","id":"1"}],"modified":"2017-01-23T02:20:09.331Z"}`))
					if err != nil {
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					w.WriteHeader(http.StatusOK)
					return
				}
				if r.URL.Path == "/domain/dummyDom/service/zts" {
					w.Header().Add("ETag", "dummyETag")
					_, err := w.Write([]byte(`{"name":"dummyDom.zts","publicKeys":[{"key":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FEVTU3VEVoWW5xUkRNM0R2UUM4ajNQSU1FeAp1M3JtYW9QakV6SnlRWTFrVm42MEE2cXJKTDJ1N3N2NHNTa1V5NjdJSUlhQ1VXNVp4aTRXUEdyazAvQm9oMDlGCkJWL1ZML0dMMTB6UmFvcDJXT3ZXRTlpSWNzKzJOK2pWTk1ycVhxZUNENFphK2dHdGdLTU5SMldiRlQvQlcra0wKUGlGeGg0U0NsVkZrdmI4Mm93SURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQ--","id":"0"}],"modified":"2017-01-23T02:20:09.331Z"}`))
					if err != nil {
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					w.WriteHeader(http.StatusOK)
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			srv := httptest.NewTLSServer(handler)

			return test{
				name: "test pubkeys fetch success",
				fields: fields{
					athenzURL:     strings.Replace(srv.URL, "https://", "", 1),
					sysAuthDomain: "dummyDom",
					eTagCache:     gache.New(),
					eTagExpiry:    time.Minute,
					client:        srv.Client(),
					confCache: &AthenzConfig{
						ZMSPubKeys: new(sync.Map),
						ZTSPubKeys: new(sync.Map),
					},
				},
				args: args{
					ctx: context.Background(),
				},
				checkFunc: func(c *pubkeyd, gotErr error) error {
					if gotErr != nil {
						return gotErr
					}
					ind := 0
					var err error
					checker := func(key interface{}, value interface{}) bool {
						ind++
						valType := fmt.Sprint(reflect.TypeOf(value))
						if valType != "*zmssvctoken.verify" {
							err = errors.Errorf("Pubkey Map key:%s is not Verifier. result: %s", key, valType)
							return false
						}
						return true
					}
					c.confCache.ZMSPubKeys.Range(checker)
					if ind != 2 {
						return errors.Errorf("invalid length ZMSPubKeys. want: 2, result: %d", ind)
					}
					if err != nil {
						return err
					}
					err = nil
					ind = 0
					c.confCache.ZTSPubKeys.Range(checker)
					if ind != 1 {
						return errors.Errorf("invalid length ZTSPubKeys. want: 1, result: %d", ind)
					}
					if err != nil {
						return err
					}
					return nil
				},
			}
		}(),
		func() test {
			handler := http.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("If-None-Match") == "dummyETag" {
					w.WriteHeader(http.StatusNotModified)
				} else {
					w.Header().Add("ETag", "dummyNEWETag")
					w.WriteHeader(http.StatusOK)
				}
			}))
			srv := httptest.NewTLSServer(handler)
			ec := gache.New()
			ec.Set("zms", &confCache{
				eTag: "dummyETag",
				sac: &SysAuthConfig{
					Modified: "2017-01-23T02:20:09.331Z",
					Name:     "dummyDom.zms",
					PublicKeys: []*PublicKey{
						{
							ID:  "dummyID",
							Key: "dummyKey",
						},
					},
				},
			})
			ec.Set("zts", &confCache{
				eTag: "dummyETag",
				sac: &SysAuthConfig{
					Modified: "2017-01-23T02:20:09.331Z",
					Name:     "dummyDom.zts",
					PublicKeys: []*PublicKey{
						{
							ID:  "dummyID",
							Key: "dummyKey",
						},
					},
				},
			})

			zmsVer := &VerifierMock{}
			ztsVer := &VerifierMock{}
			zmsVM := new(sync.Map)
			ztsVM := new(sync.Map)
			zmsVM.Store("zms", zmsVer)
			ztsVM.Store("zts", ztsVer)
			return test{
				name: "test use ETag cache",
				fields: fields{
					athenzURL:     strings.Replace(srv.URL, "https://", "", 1),
					sysAuthDomain: "dummyDom",
					eTagCache:     ec,
					eTagExpiry:    time.Minute,
					client:        srv.Client(),
					confCache: &AthenzConfig{
						ZMSPubKeys: zmsVM,
						ZTSPubKeys: ztsVM,
					},
				},
				args: args{
					ctx: context.Background(),
				},
				checkFunc: func(c *pubkeyd, gotErr error) error {
					if gotErr != nil {
						return gotErr
					}
					ind := 0
					var err error
					checker := func(key interface{}, value interface{}) bool {
						ind++
						want := zmsVer
						if key.(string) == "zts" {
							want = ztsVer
						}
						if value.(*VerifierMock) != want {
							err = errors.Errorf("Pubkey Map key:%s  invalid Verifier.", key)
							return false
						}
						return true
					}
					c.confCache.ZMSPubKeys.Range(checker)
					if ind != 1 {
						return errors.Errorf("invalid length ZMSPubKeys. want: 1, result: %d", ind)
					}
					if err != nil {
						return err
					}
					err = nil
					ind = 0
					c.confCache.ZTSPubKeys.Range(checker)
					if ind != 1 {
						return errors.Errorf("invalid length ZTSPubKeys. want: 1, result: %d", ind)
					}
					if err != nil {
						return err
					}
					return nil
				},
			}
		}(),
		func() test {
			handler := http.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/domain/dummyDom/service/zms" {
					w.Header().Add("ETag", "dummyETag")
					w.WriteHeader(http.StatusOK)
					return
				}
				if r.URL.Path == "/domain/dummyDom/service/zts" {
					w.Header().Add("ETag", "dummyETag")
					_, err := w.Write([]byte(`{"name":"dummyDom.zts","publicKeys":[{"key":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FEVTU3VEVoWW5xUkRNM0R2UUM4ajNQSU1FeAp1M3JtYW9QakV6SnlRWTFrVm42MEE2cXJKTDJ1N3N2NHNTa1V5NjdJSUlhQ1VXNVp4aTRXUEdyazAvQm9oMDlGCkJWL1ZML0dMMTB6UmFvcDJXT3ZXRTlpSWNzKzJOK2pWTk1ycVhxZUNENFphK2dHdGdLTU5SMldiRlQvQlcra0wKUGlGeGg0U0NsVkZrdmI4Mm93SURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQ--","id":"0"}],"modified":"2017-01-23T02:20:09.331Z"}`))
					if err != nil {
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					w.WriteHeader(http.StatusOK)
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			srv := httptest.NewTLSServer(handler)

			return test{
				name: "test fetchPubKeyEntries returns error",
				fields: fields{
					athenzURL:     strings.Replace(srv.URL, "https://", "", 1),
					sysAuthDomain: "dummyDom",
					eTagCache:     gache.New(),
					eTagExpiry:    time.Minute,
					client:        srv.Client(),
					confCache: &AthenzConfig{
						ZMSPubKeys: new(sync.Map),
						ZTSPubKeys: new(sync.Map),
					},
				},
				args: args{
					ctx: context.Background(),
				},
				checkFunc: func(c *pubkeyd, gotErr error) error {
					wantErr := "error when processing pubkey: Error updating ZMS athenz pubkey: error fetch public key entries: json format not correct: EOF"
					if gotErr.Error() != wantErr {
						return errors.Wrap(gotErr, "unexpected error")
					}
					return nil
				},
			}
		}(),
		func() test {
			handler := http.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/domain/dummyDom/service/zms" {
					w.Header().Add("ETag", "dummyETag")
					_, err := w.Write([]byte(`{"name":"dummyDom.zms","publicKeys":[{"key":"cannot decode","id":"0"}],"modified":"2017-01-23T02:20:09.331Z"}`))
					if err != nil {
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					w.WriteHeader(http.StatusOK)
					return
				}
				if r.URL.Path == "/domain/dummyDom/service/zts" {
					w.Header().Add("ETag", "dummyETag")
					_, err := w.Write([]byte(`{"name":"dummyDom.zts","publicKeys":[{"key":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FEVTU3VEVoWW5xUkRNM0R2UUM4ajNQSU1FeAp1M3JtYW9QakV6SnlRWTFrVm42MEE2cXJKTDJ1N3N2NHNTa1V5NjdJSUlhQ1VXNVp4aTRXUEdyazAvQm9oMDlGCkJWL1ZML0dMMTB6UmFvcDJXT3ZXRTlpSWNzKzJOK2pWTk1ycVhxZUNENFphK2dHdGdLTU5SMldiRlQvQlcra0wKUGlGeGg0U0NsVkZrdmI4Mm93SURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQ--","id":"0"}],"modified":"2017-01-23T02:20:09.331Z"}`))
					if err != nil {
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					w.WriteHeader(http.StatusOK)
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			srv := httptest.NewTLSServer(handler)

			return test{
				name: "test cannot decode key",
				fields: fields{
					athenzURL:     strings.Replace(srv.URL, "https://", "", 1),
					sysAuthDomain: "dummyDom",
					eTagCache:     gache.New(),
					eTagExpiry:    time.Minute,
					client:        srv.Client(),
					confCache: &AthenzConfig{
						ZMSPubKeys: new(sync.Map),
						ZTSPubKeys: new(sync.Map),
					},
				},
				args: args{
					ctx: context.Background(),
				},
				checkFunc: func(c *pubkeyd, gotErr error) error {
					wantErr := "error when processing pubkey: Error updating ZMS athenz pubkey: error decoding key: illegal base64 data at input byte 6"
					if gotErr.Error() != wantErr {
						return errors.Wrap(gotErr, "unexpected error")
					}
					return nil
				},
			}
		}(),
		func() test {
			handler := http.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/domain/dummyDom/service/zms" {
					w.Header().Add("ETag", "dummyETag")
					_, err := w.Write([]byte(`{"name":"dummyDom.zms","publicKeys":[{"key":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FEVTU3VEVoWW5xUkRNM0R2UUM4ajNQSU1FeAp1M3JtYW9QakV6SnlRWTFrVm42MEE2cXJKTDJ1N3N2NHNTa1V5NjdJSUlhQ1VXNVp4aTRXUEdyazAvQm9oMDlGCkJWL1ZML0dMMTB6UmFvcDJXT3ZXRTlpSWNzKzJOK2pWTk1ycVhxZUNENFphK2dHdGdLTU5SMldiRlQvQlcra0wKUGlGeGg0U0NsVkZrdmI4Mm93SURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQ--","id":"0"}],"modified":"2017-01-23T02:20:09.331Z"}`))
					if err != nil {
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					w.WriteHeader(http.StatusOK)
					return
				}
				if r.URL.Path == "/domain/dummyDom/service/zts" {
					w.Header().Add("ETag", "dummyETag")
					_, err := w.Write([]byte(`{"name":"dummyDom.zts","publicKeys":[{"key":"ZHVtbXkga2V5Cg--","id":"0"}],"modified":"2017-01-23T02:20:09.331Z"}`))
					if err != nil {
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					w.WriteHeader(http.StatusOK)
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			srv := httptest.NewTLSServer(handler)

			return test{
				name: "test cannot new verifier",
				fields: fields{
					athenzURL:     strings.Replace(srv.URL, "https://", "", 1),
					sysAuthDomain: "dummyDom",
					eTagCache:     gache.New(),
					eTagExpiry:    time.Minute,
					client:        srv.Client(),
					confCache: &AthenzConfig{
						ZMSPubKeys: new(sync.Map),
						ZTSPubKeys: new(sync.Map),
					},
				},
				args: args{
					ctx: context.Background(),
				},
				checkFunc: func(c *pubkeyd, gotErr error) error {
					wantErr := "error when processing pubkey: Error updating ZTS athenz pubkey: error initializing verifier: Unable to load public key"
					if gotErr.Error() != wantErr {
						return errors.Wrap(gotErr, "unexpected error")
					}
					return nil
				},
			}
		}(),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &pubkeyd{
				refreshPeriod:   tt.fields.refreshPeriod,
				retryDelay:      tt.fields.retryDelay,
				eTagCache:       tt.fields.eTagCache,
				eTagPurgePeriod: tt.fields.eTagPurgePeriod,
				eTagExpiry:      tt.fields.eTagExpiry,
				athenzURL:       tt.fields.athenzURL,
				sysAuthDomain:   tt.fields.sysAuthDomain,
				client:          tt.fields.client,
				confCache:       tt.fields.confCache,
			}
			err := c.Update(tt.args.ctx)
			if err = tt.checkFunc(c, err); err != nil {
				t.Errorf("c.Update() error = %v", err)
			}
		})
	}
}

func Test_pubkeyd_Start(t *testing.T) {
	type fields struct {
		refreshPeriod   time.Duration
		retryDelay      time.Duration
		eTagCache       gache.Gache
		eTagPurgePeriod time.Duration
		eTagExpiry      time.Duration
		athenzURL       string
		sysAuthDomain   string
		client          *http.Client
		confCache       *AthenzConfig
	}
	type args struct {
		ctx context.Context
	}
	type test struct {
		name      string
		fields    fields
		args      args
		checkFunc func(*pubkeyd, <-chan error) error
	}
	tests := []test{
		func() test {
			handler := http.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/domain/dummyDom/service/zms" {
					w.Header().Add("ETag", "dummy-zms-etag")
					_, err := w.Write([]byte(`{"name":"dummyDom.zms","publicKeys":[{"key":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FEVTU3VEVoWW5xUkRNM0R2UUM4ajNQSU1FeAp1M3JtYW9QakV6SnlRWTFrVm42MEE2cXJKTDJ1N3N2NHNTa1V5NjdJSUlhQ1VXNVp4aTRXUEdyazAvQm9oMDlGCkJWL1ZML0dMMTB6UmFvcDJXT3ZXRTlpSWNzKzJOK2pWTk1ycVhxZUNENFphK2dHdGdLTU5SMldiRlQvQlcra0wKUGlGeGg0U0NsVkZrdmI4Mm93SURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQ--","id":"0"}],"modified":"2017-01-23T02:20:09.331Z"}`))
					if err != nil {
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					w.WriteHeader(http.StatusOK)
					return
				}
				if r.URL.Path == "/domain/dummyDom/service/zts" {
					w.Header().Add("ETag", "dummy-zts-etag")
					_, err := w.Write([]byte(`{"name":"dummyDom.zts","publicKeys":[{"key":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FEVTU3VEVoWW5xUkRNM0R2UUM4ajNQSU1FeAp1M3JtYW9QakV6SnlRWTFrVm42MEE2cXJKTDJ1N3N2NHNTa1V5NjdJSUlhQ1VXNVp4aTRXUEdyazAvQm9oMDlGCkJWL1ZML0dMMTB6UmFvcDJXT3ZXRTlpSWNzKzJOK2pWTk1ycVhxZUNENFphK2dHdGdLTU5SMldiRlQvQlcra0wKUGlGeGg0U0NsVkZrdmI4Mm93SURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQ--","id":"0"}],"modified":"2017-01-23T02:20:09.331Z"}`))
					if err != nil {
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					w.WriteHeader(http.StatusOK)
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			srv := httptest.NewTLSServer(handler)
			ctx, cancel := context.WithCancel(context.Background())

			return test{
				name: "test start pubkey updater and ctx.done",
				fields: fields{
					athenzURL:       strings.Replace(srv.URL, "https://", "", 1),
					sysAuthDomain:   "dummyDom",
					refreshPeriod:   time.Minute,
					retryDelay:      time.Minute,
					eTagCache:       gache.New(),
					eTagExpiry:      time.Minute,
					eTagPurgePeriod: time.Minute,
					client:          srv.Client(),
					confCache: &AthenzConfig{
						ZMSPubKeys: new(sync.Map),
						ZTSPubKeys: new(sync.Map),
					},
				},
				args: args{
					ctx: ctx,
				},
				checkFunc: func(c *pubkeyd, ch <-chan error) error {
					cancel()
					err := <-ch

					// check error
					wantErr := context.Canceled
					if err != wantErr {
						return fmt.Errorf("got: %v, want: %v", err, wantErr)
					}
					for err := range ch {
						if err != nil {
							return err
						}
					}
					err = nil

					// check pubkey cache
					ind := 0
					checker := func(key interface{}, value interface{}) bool {
						ind++
						valType := fmt.Sprint(reflect.TypeOf(value))
						if valType != "*zmssvctoken.verify" {
							err = errors.Errorf("Pubkey Map key:%s is not Verifier. result: %s", key, valType)
							return false
						}
						return true
					}
					check := func(m *sync.Map, wc int) error {
						m.Range(checker)
						if ind != wc {
							return errors.Errorf("invalid length ZMSPubKeys. want: %d, result: %d", wc, ind)
						}
						if err != nil {
							return err
						}
						return nil
					}
					err = check(c.confCache.ZMSPubKeys, 0)
					if err != nil {
						return err
					}
					err = nil
					ind = 0
					err = check(c.confCache.ZTSPubKeys, 0)
					if err != nil {
						return err
					}

					// check ETag cache
					ecLen := len(c.eTagCache.ToRawMap(context.Background()))
					wantEcLen := 0
					if ecLen != wantEcLen {
						return errors.Errorf("invalid length ZMSPubKeys. got: %d, want: %d", ecLen, wantEcLen)
					}
					c.eTagCache.Foreach(context.Background(), func(key string, val interface{}, _ int64) bool {
						if key != "zms" && key != "zts" {
							err = errors.Errorf("unexpected key %s", key)
							return false
						}
						wantETag := fmt.Sprintf("dummy-%s-etag", key)
						if val.(*confCache).eTag != wantETag {
							err = errors.Errorf("unexpected ETag %s", val.(*confCache).eTag)
							return false
						}
						return true
					})
					if err != nil {
						return err
					}

					return nil
				},
			}
		}(),
		func() test {
			handler := http.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/domain/dummyDom/service/zms" {
					w.Header().Add("ETag", "dummy-zms-etag")
					_, err := w.Write([]byte(`{"name":"dummyDom.zms","publicKeys":[{"key":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FEVTU3VEVoWW5xUkRNM0R2UUM4ajNQSU1FeAp1M3JtYW9QakV6SnlRWTFrVm42MEE2cXJKTDJ1N3N2NHNTa1V5NjdJSUlhQ1VXNVp4aTRXUEdyazAvQm9oMDlGCkJWL1ZML0dMMTB6UmFvcDJXT3ZXRTlpSWNzKzJOK2pWTk1ycVhxZUNENFphK2dHdGdLTU5SMldiRlQvQlcra0wKUGlGeGg0U0NsVkZrdmI4Mm93SURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQ--","id":"0"}],"modified":"2017-01-23T02:20:09.331Z"}`))
					if err != nil {
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					w.WriteHeader(http.StatusOK)
					return
				}
				if r.URL.Path == "/domain/dummyDom/service/zts" {
					w.Header().Add("ETag", "dummy-zts-etag")
					w.WriteHeader(http.StatusOK)
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			srv := httptest.NewTLSServer(handler)
			ctx, cancel := context.WithCancel(context.Background())

			return test{
				name: "test Update failed",
				fields: fields{
					athenzURL:       strings.Replace(srv.URL, "https://", "", 1),
					sysAuthDomain:   "dummyDom",
					refreshPeriod:   10 * time.Millisecond,
					retryDelay:      time.Minute,
					eTagCache:       gache.New(),
					eTagExpiry:      time.Minute,
					eTagPurgePeriod: time.Minute,
					client:          srv.Client(),
					confCache: &AthenzConfig{
						ZMSPubKeys: new(sync.Map),
						ZTSPubKeys: new(sync.Map),
					},
				},
				args: args{
					ctx: ctx,
				},
				checkFunc: func(c *pubkeyd, ch <-chan error) error {
					gotErr := <-ch
					cancel()

					wantErr := "error update pubkey: error when processing pubkey: Error updating ZTS athenz pubkey: error fetch public key entries: json format not correct: EOF"
					if gotErr.Error() != wantErr {
						return errors.Errorf("got: %s, want: %s", gotErr, wantErr)
					}
					return nil
				},
			}
		}(),
		func() test {
			ztsc := 0
			zmsc := 0
			handler := http.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/domain/dummyDom/service/zms" {
					if zmsc < 4 {
						zmsc++
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					w.Header().Add("ETag", fmt.Sprintf("dummy-zms-etag%d", zmsc))
					_, err := w.Write([]byte(fmt.Sprintf(`{"name":"dummyDom.zms","publicKeys":[{"key":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FEVTU3VEVoWW5xUkRNM0R2UUM4ajNQSU1FeAp1M3JtYW9QakV6SnlRWTFrVm42MEE2cXJKTDJ1N3N2NHNTa1V5NjdJSUlhQ1VXNVp4aTRXUEdyazAvQm9oMDlGCkJWL1ZML0dMMTB6UmFvcDJXT3ZXRTlpSWNzKzJOK2pWTk1ycVhxZUNENFphK2dHdGdLTU5SMldiRlQvQlcra0wKUGlGeGg0U0NsVkZrdmI4Mm93SURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQ--","id":"%d"}],"modified":"2017-01-23T02:20:09.331Z"}`, zmsc)))
					if err != nil {
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					w.WriteHeader(http.StatusOK)
					return
				}
				if r.URL.Path == "/domain/dummyDom/service/zts" {
					if ztsc < 4 {
						ztsc++
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					w.Header().Add("ETag", fmt.Sprintf("dummy-zts-etag%d", ztsc))
					_, err := w.Write([]byte(fmt.Sprintf(`{"name":"dummyDom.zts","publicKeys":[{"key":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FEVTU3VEVoWW5xUkRNM0R2UUM4ajNQSU1FeAp1M3JtYW9QakV6SnlRWTFrVm42MEE2cXJKTDJ1N3N2NHNTa1V5NjdJSUlhQ1VXNVp4aTRXUEdyazAvQm9oMDlGCkJWL1ZML0dMMTB6UmFvcDJXT3ZXRTlpSWNzKzJOK2pWTk1ycVhxZUNENFphK2dHdGdLTU5SMldiRlQvQlcra0wKUGlGeGg0U0NsVkZrdmI4Mm93SURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQ--","id":"%d"}],"modified":"2017-01-23T02:20:09.331Z"}`, ztsc)))
					if err != nil {
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					w.WriteHeader(http.StatusOK)
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			srv := httptest.NewTLSServer(handler)
			ctx, cancel := context.WithCancel(context.Background())

			return test{
				name: "test refresh pubkey",
				fields: fields{
					athenzURL:       strings.Replace(srv.URL, "https://", "", 1),
					sysAuthDomain:   "dummyDom",
					refreshPeriod:   time.Millisecond * 3,
					retryDelay:      time.Millisecond,
					eTagCache:       gache.New(),
					eTagExpiry:      time.Minute,
					eTagPurgePeriod: time.Minute,
					client:          srv.Client(),
					confCache: &AthenzConfig{
						ZMSPubKeys: new(sync.Map),
						ZTSPubKeys: new(sync.Map),
					},
				},
				args: args{
					ctx: ctx,
				},
				checkFunc: func(c *pubkeyd, ch <-chan error) error {
					go func() {
						for {
							<-ch
						}
					}()
					time.Sleep(time.Millisecond * 100)
					cancel()
					time.Sleep(time.Millisecond * 100)
					ind := 0
					var err error

					c.eTagCache.Foreach(context.Background(), func(key string, val interface{}, _ int64) bool {
						if key != "zms" && key != "zts" {
							err = errors.Errorf("unexpected key %s", key)
							return false
						}
						wantETag := fmt.Sprintf("dummy-%s-etag%d", key, 4)
						if val.(*confCache).eTag != wantETag {
							err = errors.Errorf("unexpected ETag %s, want: %s", val.(*confCache).eTag, wantETag)
							return false
						}
						return true
					})

					checker := func(key interface{}, value interface{}) bool {
						ind++
						valType := fmt.Sprint(reflect.TypeOf(value))
						if valType != "*zmssvctoken.verify" {
							err = errors.Errorf("Pubkey Map key:%s is not Verifier. result: %s", key, valType)
							return false
						}
						return true
					}
					check := func(m *sync.Map, wc int, env string) error {
						m.Range(checker)
						if ind != wc {
							return errors.Errorf("invalid length %s PubKeys. want: %d, result: %d", env, wc, ind)
						}
						if err != nil {
							return err
						}
						return nil
					}
					err = check(c.confCache.ZMSPubKeys, 1, "ZMS")
					if err != nil {
						return err
					}
					err = nil
					ind = 0
					err = check(c.confCache.ZTSPubKeys, 1, "ZTS")
					if err != nil {
						return err
					}
					err = nil
					ind = 0
					return nil
				},
			}
		}(),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &pubkeyd{
				refreshPeriod:   tt.fields.refreshPeriod,
				retryDelay:      tt.fields.retryDelay,
				eTagCache:       tt.fields.eTagCache,
				eTagPurgePeriod: tt.fields.eTagPurgePeriod,
				eTagExpiry:      tt.fields.eTagExpiry,
				athenzURL:       tt.fields.athenzURL,
				sysAuthDomain:   tt.fields.sysAuthDomain,
				client:          tt.fields.client,
				confCache:       tt.fields.confCache,
			}
			ch := c.Start(tt.args.ctx)
			if err := tt.checkFunc(c, ch); err != nil {
				t.Errorf("c.Start() error = %v", err)
			}
		})
	}
}
