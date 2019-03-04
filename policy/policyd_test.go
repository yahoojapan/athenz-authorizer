package policy

import (
	"context"
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
	"github.com/yahoojapan/athenz-policy-updater/config"
)

func TestNewPolicyd(t *testing.T) {
	type args struct {
		opts []Option
	}
	tests := []struct {
		name      string
		args      args
		want      Policyd
		checkFunc func(got Policyd) error
		wantErr   bool
	}{
		/*
			{
				name: "new success",
				args: args{
					opts: []Option{},
				},
				checkFunc: func(got Policyd) error {
					p := got.(*policy)

					return fmt.Errorf("%v", p)
				},
			},
		*/
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewPolicyd(tt.args.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewPolicyd() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err := tt.checkFunc(got); err != nil {
				t.Errorf("NewPolicyd() = %v", err)
			}
		})
	}
}

func Test_policy_StartPolicyUpdator(t *testing.T) {
	type fields struct {
		expireMargin     time.Duration
		rolePolicies     gache.Gache
		refreshDuration  time.Duration
		errRetryInterval time.Duration
		pkp              config.PubKeyProvider
		etagCache        gache.Gache
		etagFlushDur     time.Duration
		etagExpTime      time.Duration
		athenzURL        string
		athenzDomains    []string
		client           *http.Client
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   <-chan error
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &policy{
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
			if got := p.StartPolicyUpdator(tt.args.ctx); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("policy.StartPolicyUpdator() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_policy_UpdatePolicy(t *testing.T) {
	type fields struct {
		expireMargin     time.Duration
		rolePolicies     gache.Gache
		refreshDuration  time.Duration
		errRetryInterval time.Duration
		pkp              config.PubKeyProvider
		etagCache        gache.Gache
		etagFlushDur     time.Duration
		etagExpTime      time.Duration
		athenzURL        string
		athenzDomains    []string
		client           *http.Client
	}
	type args struct {
		ctx context.Context
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
			p := &policy{
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
			if err := p.UpdatePolicy(tt.args.ctx); (err != nil) != tt.wantErr {
				t.Errorf("policy.UpdatePolicy() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_policy_CheckPolicy(t *testing.T) {
	type fields struct {
		expireMargin     time.Duration
		rolePolicies     gache.Gache
		refreshDuration  time.Duration
		errRetryInterval time.Duration
		pkp              config.PubKeyProvider
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
			p := &policy{
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
			if err := p.CheckPolicy(tt.args.ctx, tt.args.domain, tt.args.roles, tt.args.action, tt.args.resource); (err != nil) != tt.wantErr {
				t.Errorf("policy.CheckPolicy() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_policy_fetchAndCachePolicy(t *testing.T) {
	type fields struct {
		expireMargin     time.Duration
		rolePolicies     gache.Gache
		refreshDuration  time.Duration
		errRetryInterval time.Duration
		pkp              config.PubKeyProvider
		etagCache        gache.Gache
		etagFlushDur     time.Duration
		etagExpTime      time.Duration
		athenzURL        string
		athenzDomains    []string
		client           *http.Client
	}
	type args struct {
		ctx context.Context
		dom string
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
			p := &policy{
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
			if err := p.fetchAndCachePolicy(tt.args.ctx, tt.args.dom); (err != nil) != tt.wantErr {
				t.Errorf("policy.fetchAndCachePolicy() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_policy_fetchPolicy(t *testing.T) {
	type fields struct {
		expireMargin     time.Duration
		rolePolicies     gache.Gache
		refreshDuration  time.Duration
		errRetryInterval time.Duration
		pkp              config.PubKeyProvider
		etagCache        gache.Gache
		etagFlushDur     time.Duration
		etagExpTime      time.Duration
		athenzURL        string
		athenzDomains    []string
		client           *http.Client
	}
	type args struct {
		ctx    context.Context
		domain string
	}
	type test struct {
		name      string
		fields    fields
		args      args
		checkFunc func(p *policy, sp *SignedPolicy, upd bool, err error) error
	}
	tests := []test{
		func() test {
			handler := http.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Add("ETag", "dummyEtag")
				w.Write([]byte(`{"signedPolicyData":{"zmsKeyId":"1"}}`))
				w.WriteHeader(http.StatusOK)
			}))
			srv := httptest.NewTLSServer(handler)

			return test{
				name: "test fetch success",
				fields: fields{
					athenzURL:    strings.Replace(srv.URL, "https://", "", 1),
					etagCache:    gache.New(),
					etagExpTime:  time.Minute,
					expireMargin: time.Hour,
					client:       srv.Client(),
					pkp: func(e config.AthenzEnv, id string) authcore.Verifier {
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
				checkFunc: func(p *policy, sp *SignedPolicy, upd bool, err error) error {
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

					if !cmp.Equal(etagCac.sp, want) {
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
					athenzURL:    " ",
					etagCache:    gache.New(),
					etagExpTime:  time.Minute,
					expireMargin: time.Second,
					client:       srv.Client(),
					pkp: func(e config.AthenzEnv, id string) authcore.Verifier {
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
				checkFunc: func(p *policy, sp *SignedPolicy, upd bool, err error) error {
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
							Expires: &rdl.Timestamp{
								time.Now().Add(time.Hour).UTC(),
							},
						},
					},
				},
			})

			return test{
				name: "test etag exists",
				fields: fields{
					athenzURL:    strings.Replace(srv.URL, "https://", "", 1),
					etagCache:    etagCac,
					etagExpTime:  time.Minute,
					expireMargin: time.Second,
					client:       srv.Client(),
					pkp: func(e config.AthenzEnv, id string) authcore.Verifier {
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
				checkFunc: func(p *policy, sp *SignedPolicy, upd bool, err error) error {
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
			}))
			srv := httptest.NewTLSServer(handler)

			return test{
				name: "test fetch error make https request",
				fields: fields{
					athenzURL:    "dummyURL",
					etagCache:    gache.New(),
					etagExpTime:  time.Minute,
					expireMargin: time.Hour,
					client:       srv.Client(),
					pkp: func(e config.AthenzEnv, id string) authcore.Verifier {
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
				checkFunc: func(p *policy, sp *SignedPolicy, upd bool, err error) error {
					if sp != nil {
						return errors.Errorf("sp should be nil")
					}
					if upd != false {
						return errors.New("Invalid upd flag")
					}
					wantErr := "error making request: Get https://dummyURL/domain/dummyDomain/signed_policy_data: dial tcp: lookup dummyURL: no such host"
					if err.Error() != wantErr {
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
					athenzURL:    strings.Replace(srv.URL, "https://", "", 1),
					etagCache:    gache.New(),
					etagExpTime:  time.Minute,
					expireMargin: time.Hour,
					client:       srv.Client(),
					pkp: func(e config.AthenzEnv, id string) authcore.Verifier {
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
				checkFunc: func(p *policy, sp *SignedPolicy, upd bool, err error) error {
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
					athenzURL:    strings.Replace(srv.URL, "https://", "", 1),
					etagCache:    gache.New(),
					etagExpTime:  time.Minute,
					expireMargin: time.Hour,
					client:       srv.Client(),
					pkp: func(e config.AthenzEnv, id string) authcore.Verifier {
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
				checkFunc: func(p *policy, sp *SignedPolicy, upd bool, err error) error {
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
				w.Write([]byte(`{"signedPolicyData":{"zmsKeyId":"1"}}`))
			}))
			srv := httptest.NewTLSServer(handler)

			return test{
				name: "test fetch verify error",
				fields: fields{
					athenzURL:    strings.Replace(srv.URL, "https://", "", 1),
					etagCache:    gache.New(),
					etagExpTime:  time.Minute,
					expireMargin: time.Hour,
					client:       srv.Client(),
					pkp: func(e config.AthenzEnv, id string) authcore.Verifier {
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
				checkFunc: func(p *policy, sp *SignedPolicy, upd bool, err error) error {
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
			p := &policy{
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
			got, got1, err := p.fetchPolicy(tt.args.ctx, tt.args.domain)

			if err := tt.checkFunc(p, got, got1, err); err != nil {
				t.Errorf("policy.fetchPolicy() error = %v", err)
			}

			/*
				if (err != nil) != tt.wantErr {
					t.Errorf("policy.fetchPolicy() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("policy.fetchPolicy() got = %v, want %v", got, tt.want)
				}
				if got1 != tt.want1 {
					t.Errorf("policy.fetchPolicy() got1 = %v, want %v", got1, tt.want1)
				}
			*/
		})
	}
}
