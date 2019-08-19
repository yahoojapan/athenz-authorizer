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
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ardielle/ardielle-go/rdl"
	"github.com/kpango/fastime"
	"github.com/pkg/errors"
	authcore "github.com/yahoo/athenz/libs/go/zmssvctoken"
	"github.com/yahoo/athenz/utils/zpe-updater/util"
	"github.com/yahoojapan/athenz-authorizer/pubkey"
)

func Test_flushAndClose(t *testing.T) {
	type args struct {
		readCloser io.ReadCloser
	}
	type testcase struct {
		name      string
		args      args
		wantError error
	}
	tests := []testcase{
		{
			name: "Check flushAndClose, readCloser is nil",
			args: args{
				readCloser: nil,
			},
			wantError: nil,
		},
		{
			name: "Check flushAndClose, flush & close success",
			args: args{
				readCloser: &readCloserMock{
					readMock: func(p []byte) (n int, err error) {
						return 0, io.EOF
					},
					closeMock: func() error {
						return nil
					},
				},
			},
			wantError: nil,
		},
		{
			name: "Check flushAndClose, flush fail",
			args: args{
				readCloser: &readCloserMock{
					readMock: func(p []byte) (n int, err error) {
						return 0, fmt.Errorf("read-error-1332")
					},
					closeMock: func() error {
						return nil
					},
				},
			},
			wantError: fmt.Errorf("read-error-1332"),
		},
		{
			name: "Check flushAndClose, close fail",
			args: args{
				readCloser: &readCloserMock{
					readMock: func(p []byte) (n int, err error) {
						return 0, io.EOF
					},
					closeMock: func() error {
						return fmt.Errorf("close-error-1349")
					},
				},
			},
			wantError: fmt.Errorf("close-error-1349"),
		},
		{
			name: "Check flushAndClose, flush & close fail",
			args: args{
				readCloser: &readCloserMock{
					readMock: func(p []byte) (n int, err error) {
						return 0, fmt.Errorf("read-error-1360")
					},
					closeMock: func() error {
						return fmt.Errorf("close-error-1363")
					},
				},
			},
			wantError: fmt.Errorf("read-error-1360"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotError := flushAndClose(tt.args.readCloser)
			if !reflect.DeepEqual(gotError, tt.wantError) {
				t.Errorf("flushAndClose() error = %v, want %v", gotError, tt.wantError)
			}
		})
	}
}

func Test_fetcher_Init(t *testing.T) {
	type fields struct {
		domain        string
		expireMargin  time.Duration
		retryInterval time.Duration
		retryMaxCount int
		athenzURL     string
		spVerifier    SignedPolicyVerifier
		client        *http.Client
		policyCache   atomic.Value
	}
	tests := []struct {
		name      string
		fields    fields
		checkFunc func(*fetcher) error
	}{
		{
			name:   "policy cache initialize",
			fields: fields{},
			checkFunc: func(got *fetcher) error {
				gotCache := got.policyCache.Load()
				if gotCache == nil {
					return errors.New("policy cache == nil")
				}
				tp := gotCache.(*taggedPolicy)
				if tp.etagExpiry != (time.Time{}) {
					return errors.New("policy cache etagExpiry NOT initialized")
				}
				if fastime.Now().Add(3 * time.Second).Before(tp.ctime) {
					return errors.New("policy cache ctime NOT initialized")
				}
				return nil
			},
		},
		{
			name: "initialized policy cache is not overwritten",
			fields: fields{
				policyCache: func() (v atomic.Value) {
					v.Store(&taggedPolicy{etag: "etag-139"})
					return v
				}(),
			},
			checkFunc: func(got *fetcher) error {
				gotCache := got.policyCache.Load()
				if gotCache == nil {
					return errors.New("policy cache == nil")
				}
				tp := gotCache.(*taggedPolicy)
				wantEtag := "etag-139"
				if tp.etag != wantEtag {
					return fmt.Errorf("cached tp etag = %v, want %v", tp.etag, wantEtag)
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fetcher{
				domain:        tt.fields.domain,
				expireMargin:  tt.fields.expireMargin,
				retryInterval: tt.fields.retryInterval,
				retryMaxCount: tt.fields.retryMaxCount,
				athenzURL:     tt.fields.athenzURL,
				spVerifier:    tt.fields.spVerifier,
				client:        tt.fields.client,
				policyCache:   tt.fields.policyCache,
			}
			f.Init()
			err := tt.checkFunc(f)
			if err != nil {
				t.Errorf("fetcher.FetchWithRetry(), %v", err)
			}
		})
	}
}
func Test_fetcher_Domain(t *testing.T) {
	type fields struct {
		expireMargin  time.Duration
		retryInterval time.Duration
		retryMaxCount int
		domain        string
		athenzURL     string
		spVerifier    SignedPolicyVerifier
		client        *http.Client
		policyCache   atomic.Value
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "get domain success",
			fields: fields{
				domain: "domain-217",
			},
			want: "domain-217",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fetcher{
				expireMargin:  tt.fields.expireMargin,
				retryInterval: tt.fields.retryInterval,
				retryMaxCount: tt.fields.retryMaxCount,
				domain:        tt.fields.domain,
				athenzURL:     tt.fields.athenzURL,
				spVerifier:    tt.fields.spVerifier,
				client:        tt.fields.client,
				policyCache:   tt.fields.policyCache,
			}
			if got := f.Domain(); got != tt.want {
				t.Errorf("fetcher.Domain() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_fetcher_Fetch(t *testing.T) {
	type fields struct {
		expireMargin  time.Duration
		retryInterval time.Duration
		retryMaxCount int
		domain        string
		athenzURL     string
		spVerifier    SignedPolicyVerifier
		client        *http.Client
		policyCache   atomic.Value
	}
	type args struct {
		ctx context.Context
	}
	type test struct {
		name            string
		fields          fields
		args            args
		want            *SignedPolicy
		wantPolicyCache *taggedPolicy
		wantErrStr      string
	}
	mockSignedPolicyVerifier := func(sp *SignedPolicy) error {
		return sp.Verify(func(e pubkey.AthenzEnv, id string) authcore.Verifier {
			return VerifierMock{
				VerifyFunc: func(d, s string) error {
					return nil
				},
			}
		})
	}
	createTestServer := func(hf http.HandlerFunc) (*httptest.Server, *http.Client, string) {
		srv := httptest.NewTLSServer(hf)
		return srv, srv.Client(), strings.Replace(srv.URL, "https://", "", 1)
	}
	createExpires := func(d time.Duration) (time.Time, string, error) {
		t := fastime.Now().Add(d).UTC().Round(time.Millisecond)
		tByte, err := rdl.Timestamp{
			Time: t,
		}.MarshalJSON()
		return t, string(tByte), err
	}
	compareTaggedPolicy := func(a, b *taggedPolicy) error {
		if a.etag != b.etag {
			return errors.New("etag")
		}
		if a.etagExpiry != b.etagExpiry {
			return errors.New("etagExpiry")
		}
		if !reflect.DeepEqual(a.sp, b.sp) {
			return errors.New("sp")
		}
		if time.Duration(math.Abs(float64(a.ctime.Sub(b.ctime)))) > 3*time.Second {
			return errors.New("ctime")
		}
		return nil
	}
	tests := []test{
		func() (t test) {
			t.name = "fetch success, no etag"

			// http response
			domain := "dummyDomain"
			expireMargin := time.Hour
			etag := "dummyEtag"
			zmsKeyID := "dummyZmsKeyId"
			expires, expiresStr, err := createExpires(2 * expireMargin)
			_, client, url := createTestServer(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/domain/dummyDomain/signed_policy_data" {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(err.Error()))
					return
				}

				w.Header().Add("ETag", etag)
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(fmt.Sprintf(`{"signedPolicyData":{
					"zmsKeyId": "%s",
					"expires": %s
				}}`, zmsKeyID, expiresStr)))
			})

			// want objects
			sp := &SignedPolicy{
				util.DomainSignedPolicyData{
					KeyId:     "",
					Signature: "",
					SignedPolicyData: &util.SignedPolicyData{
						Expires:      &rdl.Timestamp{Time: expires},
						Modified:     nil,
						PolicyData:   nil,
						ZmsKeyId:     "dummyZmsKeyId",
						ZmsSignature: "",
					},
				},
			}
			t.want = sp
			t.wantPolicyCache = &taggedPolicy{
				etag:       "dummyEtag",
				etagExpiry: expires.Add(-expireMargin),
				sp:         sp,
				ctime:      fastime.Now(),
			}
			t.wantErrStr = ""

			// test input
			var policyCache atomic.Value
			policyCache.Store(&taggedPolicy{})
			t.args = args{
				ctx: context.Background(),
			}
			t.fields = fields{
				expireMargin:  expireMargin,
				retryInterval: time.Second,
				retryMaxCount: 3,
				domain:        domain,
				athenzURL:     url,
				spVerifier:    mockSignedPolicyVerifier,
				client:        client,
				policyCache:   policyCache,
			}

			return t
		}(),
		func() (t test) {
			t.name = "fetch success, etag with 200"

			// http response
			domain := "dummyDomain"
			expireMargin := time.Hour
			etag := "dummyEtag"
			zmsKeyID := "dummyZmsKeyId"
			expires, expiresStr, err := createExpires(2 * expireMargin)
			_, client, url := createTestServer(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/domain/dummyDomain/signed_policy_data" {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(err.Error()))
					return
				}

				if r.Header.Get("If-None-Match") != "dummyEtag" {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				w.Header().Add("ETag", "dummyNewEtag")
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(fmt.Sprintf(`{"signedPolicyData":{
					"zmsKeyId": "%s",
					"expires": %s
				}}`, zmsKeyID, expiresStr)))
			})

			// want objects
			wantEtag := "dummyNewEtag"
			sp := &SignedPolicy{
				util.DomainSignedPolicyData{
					KeyId:     "",
					Signature: "",
					SignedPolicyData: &util.SignedPolicyData{
						Expires:      &rdl.Timestamp{Time: expires},
						Modified:     nil,
						PolicyData:   nil,
						ZmsKeyId:     "dummyZmsKeyId",
						ZmsSignature: "",
					},
				},
			}
			t.want = sp
			t.wantPolicyCache = &taggedPolicy{
				etag:       wantEtag,
				etagExpiry: expires.Add(-expireMargin),
				sp:         sp,
				ctime:      fastime.Now(),
			}
			t.wantErrStr = ""

			// test input
			var policyCache atomic.Value
			policyCache.Store(&taggedPolicy{
				etag:       etag,
				etagExpiry: expires.Add(-expireMargin),
			})
			t.args = args{
				ctx: context.Background(),
			}
			t.fields = fields{
				expireMargin:  expireMargin,
				retryInterval: time.Second,
				retryMaxCount: 3,
				domain:        domain,
				athenzURL:     url,
				spVerifier:    mockSignedPolicyVerifier,
				client:        client,
				policyCache:   policyCache,
			}

			return t
		}(),
		func() (t test) {
			t.name = "fetch success, etag with 304"

			// http response
			domain := "dummyDomain"
			expireMargin := time.Hour
			_, client, url := createTestServer(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/domain/dummyDomain/signed_policy_data" {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				if r.Header.Get("If-None-Match") == "dummyEtag" {
					w.WriteHeader(http.StatusNotModified)
				} else {
					w.WriteHeader(http.StatusInternalServerError)
				}
			})

			// want objects
			expires := fastime.Now().Add(2*expireMargin)
			sp := &SignedPolicy{
				util.DomainSignedPolicyData{
					KeyId:     "",
					Signature: "",
					SignedPolicyData: &util.SignedPolicyData{
						Expires:      &rdl.Timestamp{Time: expires},
						Modified:     nil,
						PolicyData:   nil,
						ZmsKeyId:     "dummyZmsKeyId",
						ZmsSignature: "",
					},
				},
			}
			t.want = sp
			t.wantPolicyCache = &taggedPolicy{
				etag:       "dummyEtag",
				etagExpiry: expires.Add(-expireMargin),
				sp:         sp,
				ctime:      fastime.Now(),
			}
			t.wantErrStr = ""

			// test input
			var policyCache atomic.Value
			policyCache.Store(t.wantPolicyCache)
			t.args = args{
				ctx: context.Background(),
			}
			t.fields = fields{
				expireMargin:  expireMargin,
				retryInterval: time.Second,
				retryMaxCount: 3,
				domain:        domain,
				athenzURL:     url,
				spVerifier:    mockSignedPolicyVerifier,
				client:        client,
				policyCache:   policyCache,
			}

			return t
		}(),
		func() (t test) {
			t.name = "fetch success, etag expiry passed, request without etag"

			// http response
			domain := "dummyDomain"
			expireMargin := time.Hour
			etag := "dummyEtag"
			zmsKeyID := "dummyZmsKeyId"
			expires, expiresStr, err := createExpires(2 * expireMargin)
			_, client, url := createTestServer(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/domain/dummyDomain/signed_policy_data" {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(err.Error()))
					return
				}

				if r.Header.Get("If-None-Match") != "" {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				w.Header().Add("ETag", etag)
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(fmt.Sprintf(`{"signedPolicyData":{
					"zmsKeyId": "%s",
					"expires": %s
				}}`, zmsKeyID, expiresStr)))
			})

			// want objects
			sp := &SignedPolicy{
				util.DomainSignedPolicyData{
					KeyId:     "",
					Signature: "",
					SignedPolicyData: &util.SignedPolicyData{
						Expires:      &rdl.Timestamp{Time: expires},
						Modified:     nil,
						PolicyData:   nil,
						ZmsKeyId:     "dummyZmsKeyId",
						ZmsSignature: "",
					},
				},
			}
			t.want = sp
			t.wantPolicyCache = &taggedPolicy{
				etag:       "dummyEtag",
				etagExpiry: expires.Add(-expireMargin),
				sp:         sp,
				ctime:      fastime.Now(),
			}
			t.wantErrStr = ""

			// test input
			var policyCache atomic.Value
			policyCache.Store(&taggedPolicy{
				etag:       "dummyOldEtag",
				etagExpiry: fastime.Now().Add(-expireMargin),
				sp:         nil,
			})
			t.args = args{
				ctx: context.Background(),
			}
			t.fields = fields{
				expireMargin:  expireMargin,
				retryInterval: time.Second,
				retryMaxCount: 3,
				domain:        domain,
				athenzURL:     url,
				spVerifier:    mockSignedPolicyVerifier,
				client:        client,
				policyCache:   policyCache,
			}

			return t
		}(),
		func() (t test) {
			t.name = "fetch success, on 304, return cached policy even if expired"

			// http response
			domain := "dummyDomain"
			expireMargin := time.Hour
			_, client, url := createTestServer(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/domain/dummyDomain/signed_policy_data" {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				if r.Header.Get("If-None-Match") == "dummyEtag" {
					w.WriteHeader(http.StatusNotModified)
				} else {
					w.WriteHeader(http.StatusInternalServerError)
				}
			})

			// want objects
			expires := fastime.Now().Add(-expireMargin)
			sp := &SignedPolicy{
				util.DomainSignedPolicyData{
					KeyId:     "",
					Signature: "",
					SignedPolicyData: &util.SignedPolicyData{
						Expires:      &rdl.Timestamp{Time: expires},
						Modified:     nil,
						PolicyData:   nil,
						ZmsKeyId:     "dummyZmsKeyId",
						ZmsSignature: "",
					},
				},
			}
			t.want = sp
			t.wantPolicyCache = &taggedPolicy{
				etag:       "dummyEtag",
				etagExpiry: fastime.Now().Add(expireMargin),
				sp:         sp,
				ctime:      fastime.Now(),
			}
			t.wantErrStr = ""

			// test input
			var policyCache atomic.Value
			policyCache.Store(t.wantPolicyCache)
			t.args = args{
				ctx: context.Background(),
			}
			t.fields = fields{
				expireMargin:  expireMargin,
				retryInterval: time.Second,
				retryMaxCount: 3,
				domain:        domain,
				athenzURL:     url,
				spVerifier:    mockSignedPolicyVerifier,
				client:        client,
				policyCache:   policyCache,
			}

			return t
		}(),
		func() (t test) {
			t.name = "fetch fail, url error"

			// http response
			domain := "dummyDomain"

			// want objects
			t.want = nil
			t.wantPolicyCache = &taggedPolicy{ctime:fastime.Now()}
			t.wantErrStr = `create fetch policy request fail: parse https:// /domain/dummyDomain/signed_policy_data: invalid character " " in host name`

			// test input
			var policyCache atomic.Value
			policyCache.Store(t.wantPolicyCache)
			t.args = args{
				ctx: context.Background(),
			}
			t.fields = fields{
				domain:        domain,
				athenzURL:     " ",
				policyCache:   policyCache,
			}

			return t
		}(),
		func() (t test) {
			t.name = "fetch fail, request error"

			// http response
			domain := "dummyDomain"
			_, client, _ := createTestServer(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			// want objects
			t.want = nil
			t.wantPolicyCache = &taggedPolicy{ctime:fastime.Now()}
			t.wantErrStr = `fetch policy HTTP request fail: Get https://non-existing-domain/domain/dummyDomain/signed_policy_data: dial tcp: lookup non-existing-domain: no such host`

			// test input
			var policyCache atomic.Value
			policyCache.Store(t.wantPolicyCache)
			t.args = args{
				ctx: context.Background(),
			}
			t.fields = fields{
				domain:        domain,
				athenzURL:     "non-existing-domain",
				client:        client,
				policyCache:   policyCache,
			}

			return t
		}(),
		func() (t test) {
			t.name = "fetch fail, server error"

			// http response
			domain := "dummyDomain"
			_, client, url := createTestServer(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			})

			// want objects
			t.want = nil
			t.wantPolicyCache = &taggedPolicy{ctime:fastime.Now()}
			t.wantErrStr = `fetch policy HTTP response != 200 OK: Error fetching athenz policy`

			// test input
			var policyCache atomic.Value
			policyCache.Store(t.wantPolicyCache)
			t.args = args{
				ctx: context.Background(),
			}
			t.fields = fields{
				domain:        domain,
				athenzURL:     url,
				client:        client,
				policyCache:   policyCache,
			}

			return t
		}(),
		func() (t test) {
			t.name = "fetch fail, policy decode error"

			// http response
			domain := "dummyDomain"
			_, client, url := createTestServer(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(""))
			})

			// want objects
			t.want = nil
			t.wantPolicyCache = &taggedPolicy{ctime:fastime.Now()}
			t.wantErrStr = `policy decode fail: EOF`

			// test input
			var policyCache atomic.Value
			policyCache.Store(t.wantPolicyCache)
			t.args = args{
				ctx: context.Background(),
			}
			t.fields = fields{
				domain:        domain,
				athenzURL:     url,
				client:        client,
				policyCache:   policyCache,
			}

			return t
		}(),
		func() (t test) {
			t.name = "fetch fail, policy verify error"

			// http response
			domain := "dummyDomain"
			_, client, url := createTestServer(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("{}"))
			})

			// want objects
			t.want = nil
			t.wantPolicyCache = &taggedPolicy{ctime:fastime.Now()}
			t.wantErrStr = `invalid policy: dummy policy verify error`

			// test input
			var policyCache atomic.Value
			policyCache.Store(t.wantPolicyCache)
			t.args = args{
				ctx: context.Background(),
			}
			t.fields = fields{
				domain:        domain,
				athenzURL:     url,
				spVerifier:    func(sp *SignedPolicy) error {
					return errors.New("dummy policy verify error")
				},
				client:        client,
				policyCache:   policyCache,
			}

			return t
		}(),
		func() (t test) {
			t.name = "fetch fail, policy verify error, null expires"

			// http response
			domain := "dummyDomain"
			_, client, url := createTestServer(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"signedPolicyData":{}}`))
			})

			// want objects
			t.want = nil
			t.wantPolicyCache = &taggedPolicy{ctime:fastime.Now()}
			t.wantErrStr = `invalid policy: policy without expiry`

			// test input
			var policyCache atomic.Value
			policyCache.Store(t.wantPolicyCache)
			t.args = args{
				ctx: context.Background(),
			}
			t.fields = fields{
				domain:        domain,
				athenzURL:     url,
				spVerifier:    mockSignedPolicyVerifier,
				client:        client,
				policyCache:   policyCache,
			}

			return t
		}(),
		func() (t test) {
			t.name = "fetch fail, policy verify error, invalid expires"

			// http response
			domain := "dummyDomain"
			_, client, url := createTestServer(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"signedPolicyData":{"expires":"2099-12-31"}}`))
			})

			// want objects
			t.want = nil
			t.wantPolicyCache = &taggedPolicy{ctime:fastime.Now()}
			t.wantErrStr = `invalid policy: policy already expired at 0001-01-01 00:00:00 +0000 UTC`

			// test input
			var policyCache atomic.Value
			policyCache.Store(t.wantPolicyCache)
			t.args = args{
				ctx: context.Background(),
			}
			t.fields = fields{
				domain:        domain,
				athenzURL:     url,
				spVerifier:    mockSignedPolicyVerifier,
				client:        client,
				policyCache:   policyCache,
			}

			return t
		}(),
		func() (t test) {
			t.name = "fetch fail, policy verify error, expired policy"

			// http response
			domain := "dummyDomain"
			_, client, url := createTestServer(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"signedPolicyData":{"expires":"2006-01-02T15:04:05.999Z"}}`))
			})

			// want objects
			t.want = nil
			t.wantPolicyCache = &taggedPolicy{ctime:fastime.Now()}
			t.wantErrStr = `invalid policy: policy already expired at 2006-01-02 15:04:05.999 +0000 UTC`

			// test input
			var policyCache atomic.Value
			policyCache.Store(t.wantPolicyCache)
			t.args = args{
				ctx: context.Background(),
			}
			t.fields = fields{
				domain:        domain,
				athenzURL:     url,
				spVerifier:    mockSignedPolicyVerifier,
				client:        client,
				policyCache:   policyCache,
			}

			return t
		}(),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fetcher{
				expireMargin:  tt.fields.expireMargin,
				retryInterval: tt.fields.retryInterval,
				retryMaxCount: tt.fields.retryMaxCount,
				domain:        tt.fields.domain,
				athenzURL:     tt.fields.athenzURL,
				spVerifier:    tt.fields.spVerifier,
				client:        tt.fields.client,
				policyCache:   tt.fields.policyCache,
			}
			got, err := f.Fetch(tt.args.ctx)
			if (err == nil && tt.wantErrStr != "") || (err != nil && err.Error() != tt.wantErrStr) {
				t.Errorf("fetcher.Fetch() error = %v, wantErr %v", err, tt.wantErrStr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("fetcher.Fetch() = %v, want %v", got.SignedPolicyData, tt.want.SignedPolicyData)
				return
			}
			gotPolicyCache := f.policyCache.Load().(*taggedPolicy)
			if err = compareTaggedPolicy(gotPolicyCache, tt.wantPolicyCache); err != nil {
				t.Errorf("fetcher.Fetch() policyCache = %v, want %v", gotPolicyCache, tt.wantPolicyCache)
				return
			}
		})
	}
}

