package config

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"
	//	"context"
	//	"net/http"
	//	"net/http/httptest"
	//	"reflect"
	//	"regexp"
	"sync"
	"testing"

	cmp "github.com/google/go-cmp/cmp"
	"github.com/kpango/gache"
	"github.com/pkg/errors"
	//	"time"
	//	ntokend "github.com/yahoojapan/athenz-ntokend"
)

func TestNewAthenzConfd(t *testing.T) {
	type args struct {
		opts []Option
	}
	type test struct {
		name      string
		args      args
		checkFunc func(AthenzConfd) error
	}
	tests := []test{
		test{
			name: "new athenz confd success",
			args: args{
				opts: []Option{},
			},
			checkFunc: func(got AthenzConfd) error {
				if got.(*confd).sysAuthDomain != "sys.auth" {
					return fmt.Errorf("cannot set default options")
				}
				return nil
			},
		},
		{
			name: "new athenz confd success with options",
			args: args{
				opts: []Option{
					SysAuthDomain("dummyd"),
					AthenzURL("dummyURL"),
				},
			},
			checkFunc: func(got AthenzConfd) error {
				if got.(*confd).sysAuthDomain != "dummyd" || got.(*confd).athenzURL != "dummyURL" {
					return fmt.Errorf("cannot set optional params")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewAthenzConfd(tt.args.opts...)
			if err != nil {
				t.Errorf("NewAthenzConfd() =  %v", err)
			}
			err = tt.checkFunc(got)
			if err != nil {
				t.Errorf("NewAthenzConfd() = %v", err)
			}
		})
	}
}

func Test_GetPubKey(t *testing.T) {
	c := &confd{
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
		want *VerifierMock
	}
	tests := []test{
		test{
			name: "get success",
			args: args{
				env:   "zts",
				keyID: "0",
			},
			want: ztsVer,
		},
		//		test{
		//			name: "not found",
		//			args: args{
		//				env: "zms",
		//				keyID: "1",
		//			},
		//			want: nil,
		//		},
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

func Test_confign_fetchPubKeyEntries(t *testing.T) {
	type fields struct {
		refreshDuration  time.Duration
		errRetryInterval time.Duration
		etagCache        gache.Gache
		etagFlushDur     time.Duration
		etagExpTime      time.Duration
		athenzURL        string
		sysAuthDomain    string
		client           *http.Client
		confCache        *AthenzConfig
	}
	type args struct {
		ctx context.Context
		env AthenzEnv
	}
	type test struct {
		name      string
		fields    fields
		args      args
		checkFunc func(c *confd, sac *SysAuthConfig, upd bool, err error) error
	}
	tests := []test{
		func() test {
			handler := http.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Add("ETag", "dummyEtag")
				w.Write([]byte(`{"name":"dummyDom.dummyEnv","publicKeys":[{"key":"dummyKey","id":"dummyID"}],"modified":"2017-01-23T02:20:09.331Z"}`))
				w.WriteHeader(http.StatusOK)
			}))
			srv := httptest.NewTLSServer(handler)

			return test{
				name:    "test fetch success",
				fields: fields{
					athenzURL:     strings.Replace(srv.URL, "https://", "", 1),
					sysAuthDomain: "dummyDom",
					etagCache:     gache.New(),
					etagExpTime:   time.Minute,
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
				checkFunc: func(c *confd, sac *SysAuthConfig, upd bool, err error) error {
					if err != nil {
						return err
					}

					_, ok := c.etagCache.Get("dummyDomain")
					if ok {
						return errors.New("invalid etag was set")
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
				if r.Header.Get("If-None-Match") == "dummyOldEtag" {
					w.WriteHeader(http.StatusNotModified)
				} else {
					w.Header().Add("ETag", "dummyNewEtag")
					w.WriteHeader(http.StatusOK)
				}
			}))
			srv := httptest.NewTLSServer(handler)

			ec := gache.New()
			ec.Set("dummyEnv", &confCache{
				eTag: "dummyOldEtag",
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
				name:    "test etag exists but not modified",
				fields: fields{
					athenzURL:     strings.Replace(srv.URL, "https://", "", 1),
					sysAuthDomain: "dummyDom",
					etagCache:     ec,
					etagExpTime:   time.Minute,
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
				checkFunc: func(c *confd, sac *SysAuthConfig, upd bool, err error) error {
					if err != nil {
						return err
					}

					etag, ok := c.etagCache.Get("dummyEnv")
					if !ok {
						return errors.New("cannot use etag cache")
					}

					want := etag.(*confCache).sac
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
				if r.Header.Get("If-None-Match") == "dummyNewEtag" {
					w.WriteHeader(http.StatusNotModified)
				} else {
					w.Header().Add("ETag", "dummyNewEtag")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"name":"dummyDom.dummyEnv","publicKeys":[{"key":"dummyNewKey","id":"dummyNewID"}],"modified":"2999-01-23T02:20:09.331Z"}`))
				}
			}))
			srv := httptest.NewTLSServer(handler)

			ec := gache.New()
			ec.Set("dummyEnv", &confCache{
				eTag: "dummyOldEtag",
				sac:  &SysAuthConfig{},
			})

			return test{
				name:    "test etag exists but modified",
				fields: fields{
					athenzURL:     strings.Replace(srv.URL, "https://", "", 1),
					sysAuthDomain: "dummyDom",
					etagCache:     ec,
					etagExpTime:   time.Minute,
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
				checkFunc: func(c *confd, sac *SysAuthConfig, upd bool, err error) error {
					if err != nil {
						return err
					}

					_, ok := c.etagCache.Get("dummyEnv")
					if !ok {
						return errors.New("cannot use etag cache")
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
				w.WriteHeader(http.StatusBadGateway)
			}))
			srv := httptest.NewTLSServer(handler)

			return test{
				name: "test not statusOK",
				fields: fields{
					athenzURL:     strings.Replace(srv.URL, "https://", "", 1),
					sysAuthDomain: "dummyDom",
					etagCache:     gache.New(),
					etagExpTime:   time.Minute,
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
				checkFunc: func(c *confd, sac *SysAuthConfig, upd bool, err error) error {
					wantErr := "http return status not OK: Fetch athenz config error"
					if err != nil {
						if err.Error() == wantErr {
							return nil
						} else {
							return errors.Errorf("unexpected error. want:%s	result:%s", wantErr, err.Error())
						}
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
				name: "test cannot make http request",
				fields: fields{
					athenzURL:     " ",
					sysAuthDomain: "dummyDom",
					etagCache:     gache.New(),
					etagExpTime:   time.Minute,
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
				checkFunc: func(c *confd, sac *SysAuthConfig, upd bool, err error) error {
					wantErr := `error creating getPub request: parse https:// /domain/dummyDom/service/dummyEnv: invalid character " " in host name`
					if err != nil {
						if err.Error() == wantErr {
							return nil
						} else {
							return errors.Errorf("unexpected error. want:%s	result:%s", wantErr, err.Error())
						}
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
					etagCache:     gache.New(),
					etagExpTime:   time.Minute,
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
				checkFunc: func(c *confd, sac *SysAuthConfig, upd bool, err error) error {
					wantErr := "json format not correct: EOF"
					if err != nil {
						if err.Error() == wantErr {
							return nil
						} else {
							return errors.Errorf("unexpected error. want:%s	result:%s", wantErr, err.Error())
						}
					}
					return errors.Errorf("http status is not OK, but fetch success")
				},
			}
		}(),

	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &confd{
				refreshDuration:  tt.fields.refreshDuration,
				errRetryInterval: tt.fields.errRetryInterval,
				etagCache:        tt.fields.etagCache,
				etagFlushDur:     tt.fields.etagFlushDur,
				etagExpTime:      tt.fields.etagExpTime,
				athenzURL:        tt.fields.athenzURL,
				sysAuthDomain:    tt.fields.sysAuthDomain,
				client:           tt.fields.client,
				confCache:        tt.fields.confCache,
			}
			got, got1, err := c.fetchPubKeyEntries(tt.args.ctx, tt.args.env)

			if err := tt.checkFunc(c, got, got1, err); err != nil {
				t.Errorf("c.fetchPubKeyEntries() error = %v", err)
			}
		})
	}
}
