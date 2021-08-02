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
	"unsafe"

	authcore "github.com/AthenZ/athenz/libs/go/zmssvctoken"
	"github.com/AthenZ/athenz/utils/zpe-updater/util"
	"github.com/ardielle/ardielle-go/rdl"
	"github.com/kpango/fastime"
	"github.com/pkg/errors"
	"github.com/yahoojapan/athenz-authorizer/v5/pubkey"
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

func Test_fetcher_Domain(t *testing.T) {
	type fields struct {
		expiryMargin  time.Duration
		retryDelay    time.Duration
		retryAttempts int
		domain        string
		athenzURL     string
		spVerifier    SignedPolicyVerifier
		client        *http.Client
		policyCache   unsafe.Pointer
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
				expiryMargin:  tt.fields.expiryMargin,
				retryDelay:    tt.fields.retryDelay,
				retryAttempts: tt.fields.retryAttempts,
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
		expiryMargin  time.Duration
		retryDelay    time.Duration
		retryAttempts int
		domain        string
		athenzURL     string
		spVerifier    SignedPolicyVerifier
		client        *http.Client
		policyCache   unsafe.Pointer
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
	dummySignedPolicyVerifier := func(sp *SignedPolicy) error {
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
		if a == b {
			return nil
		}
		if a.eTag != b.eTag {
			return errors.New("eTag")
		}
		if a.eTagExpiry != b.eTagExpiry {
			return errors.New("eTagExpiry")
		}
		if !reflect.DeepEqual(a.sp, b.sp) {
			return errors.New("sp")
		}
		if time.Duration(math.Abs(float64(a.ctime.Sub(b.ctime)))) > time.Second {
			return errors.New("ctime")
		}
		return nil
	}
	tests := []test{
		func() (t test) {
			t.name = "success, no cache"

			// http response
			domain := "dummyDomain"
			expiryMargin := time.Hour
			eTag := `"dummyEtag"`
			zmsKeyID := "dummyZmsKeyId"
			expires, expiresStr, err := createExpires(2 * expiryMargin)
			_, client, url := createTestServer(func(w http.ResponseWriter, r *http.Request) {
				handleErr := func(err error) {
					if err != nil {
						w.WriteHeader(http.StatusInternalServerError)
						_, e := w.Write([]byte(err.Error()))
						if e != nil {
							panic(e.Error())
						}
					}
				}

				if r.URL.Path != "/domain/dummyDomain/signed_policy_data" {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				if r.Header.Get("If-None-Match") != "" {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				handleErr(err)

				w.Header().Add("ETag", eTag)
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusOK)
				_, err := w.Write([]byte(fmt.Sprintf(`{"signedPolicyData":{
					"zmsKeyId": "%s",
					"expires": %s
				}}`, zmsKeyID, expiresStr)))
				handleErr(err)
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
				eTag:       `"dummyEtag"`,
				eTagExpiry: expires.Add(-expiryMargin),
				sp:         sp,
				ctime:      fastime.Now(),
			}
			t.wantErrStr = ""

			// test input
			t.args = args{
				ctx: context.Background(),
			}
			t.fields = fields{
				expiryMargin:  expiryMargin,
				retryDelay:    time.Second,
				retryAttempts: 3,
				domain:        domain,
				athenzURL:     url,
				spVerifier:    dummySignedPolicyVerifier,
				client:        client,
				// policyCache:   policyCache,
			}

			return t
		}(),
		func() (t test) {
			t.name = "success, no eTag"

			// http response
			domain := "dummyDomain"
			expiryMargin := time.Hour
			eTag := `"dummyEtag"`
			zmsKeyID := "dummyZmsKeyId"
			expires, expiresStr, err := createExpires(2 * expiryMargin)
			_, client, url := createTestServer(func(w http.ResponseWriter, r *http.Request) {
				handleErr := func(err error) {
					if err != nil {
						w.WriteHeader(http.StatusInternalServerError)
						_, e := w.Write([]byte(err.Error()))
						if e != nil {
							panic(e.Error())
						}
					}
				}

				if r.URL.Path != "/domain/dummyDomain/signed_policy_data" {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				if r.Header.Get("If-None-Match") != "" {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				handleErr(err)

				w.Header().Add("ETag", eTag)
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusOK)
				_, err := w.Write([]byte(fmt.Sprintf(`{"signedPolicyData":{
					"zmsKeyId": "%s",
					"expires": %s
				}}`, zmsKeyID, expiresStr)))
				handleErr(err)
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
				eTag:       `"dummyEtag"`,
				eTagExpiry: expires.Add(-expiryMargin),
				sp:         sp,
				ctime:      fastime.Now(),
			}
			t.wantErrStr = ""

			// test input
			policyCache := unsafe.Pointer(&taggedPolicy{})
			t.args = args{
				ctx: context.Background(),
			}
			t.fields = fields{
				expiryMargin:  expiryMargin,
				retryDelay:    time.Second,
				retryAttempts: 3,
				domain:        domain,
				athenzURL:     url,
				spVerifier:    dummySignedPolicyVerifier,
				client:        client,
				policyCache:   policyCache,
			}

			return t
		}(),
		func() (t test) {
			t.name = "success, eTag with 200"

			// http response
			domain := "dummyDomain"
			expiryMargin := time.Hour
			eTag := `"dummyEtag"`
			zmsKeyID := "dummyZmsKeyId"
			expires, expiresStr, err := createExpires(2 * expiryMargin)
			_, client, url := createTestServer(func(w http.ResponseWriter, r *http.Request) {
				handleErr := func(err error) {
					if err != nil {
						w.WriteHeader(http.StatusInternalServerError)
						_, e := w.Write([]byte(err.Error()))
						if e != nil {
							panic(e.Error())
						}
					}
				}

				if r.URL.Path != "/domain/dummyDomain/signed_policy_data" {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				if r.Header.Get("If-None-Match") != `"dummyEtag"` {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				handleErr(err)

				w.Header().Add("ETag", "dummyNewEtag")
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusOK)
				_, err := w.Write([]byte(fmt.Sprintf(`{"signedPolicyData":{
					"zmsKeyId": "%s",
					"expires": %s
				}}`, zmsKeyID, expiresStr)))
				handleErr(err)
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
				eTag:       wantEtag,
				eTagExpiry: expires.Add(-expiryMargin),
				sp:         sp,
				ctime:      fastime.Now(),
			}
			t.wantErrStr = ""

			// test input
			policyCache := unsafe.Pointer(&taggedPolicy{
				eTag:       eTag,
				eTagExpiry: expires.Add(-expiryMargin),
			})
			t.args = args{
				ctx: context.Background(),
			}
			t.fields = fields{
				expiryMargin:  expiryMargin,
				retryDelay:    time.Second,
				retryAttempts: 3,
				domain:        domain,
				athenzURL:     url,
				spVerifier:    dummySignedPolicyVerifier,
				client:        client,
				policyCache:   policyCache,
			}

			return t
		}(),
		func() (t test) {
			t.name = "success, eTag with 304"

			// http response
			domain := "dummyDomain"
			expiryMargin := time.Hour
			_, client, url := createTestServer(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/domain/dummyDomain/signed_policy_data" {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				if r.Header.Get("If-None-Match") == `"dummyEtag"` {
					w.WriteHeader(http.StatusNotModified)
					return
				}

				w.WriteHeader(http.StatusInternalServerError)
			})

			// want objects
			expires := fastime.Now().Add(2 * expiryMargin)
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
				eTag:       `"dummyEtag"`,
				eTagExpiry: expires.Add(-expiryMargin),
				sp:         sp,
				ctime:      fastime.Now(),
			}
			t.wantErrStr = ""

			// test input
			policyCache := unsafe.Pointer(t.wantPolicyCache)
			t.args = args{
				ctx: context.Background(),
			}
			t.fields = fields{
				expiryMargin:  expiryMargin,
				retryDelay:    time.Second,
				retryAttempts: 3,
				domain:        domain,
				athenzURL:     url,
				spVerifier:    dummySignedPolicyVerifier,
				client:        client,
				policyCache:   policyCache,
			}

			return t
		}(),
		func() (t test) {
			t.name = "success, eTag expiry passed, request without eTag"

			// http response
			domain := "dummyDomain"
			expiryMargin := time.Hour
			eTag := `"dummyEtag"`
			zmsKeyID := "dummyZmsKeyId"
			expires, expiresStr, err := createExpires(2 * expiryMargin)
			_, client, url := createTestServer(func(w http.ResponseWriter, r *http.Request) {
				handleErr := func(err error) {
					if err != nil {
						w.WriteHeader(http.StatusInternalServerError)
						_, e := w.Write([]byte(err.Error()))
						if e != nil {
							panic(e.Error())
						}
					}
				}

				if r.URL.Path != "/domain/dummyDomain/signed_policy_data" {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				if r.Header.Get("If-None-Match") != "" {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				handleErr(err)

				w.Header().Add("ETag", eTag)
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusOK)
				_, err := w.Write([]byte(fmt.Sprintf(`{"signedPolicyData":{
					"zmsKeyId": "%s",
					"expires": %s
				}}`, zmsKeyID, expiresStr)))
				handleErr(err)
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
				eTag:       `"dummyEtag"`,
				eTagExpiry: expires.Add(-expiryMargin),
				sp:         sp,
				ctime:      fastime.Now(),
			}
			t.wantErrStr = ""

			// test input
			policyCache := unsafe.Pointer(&taggedPolicy{
				eTag:       "dummyOldEtag",
				eTagExpiry: fastime.Now().Add(-expiryMargin),
				sp:         nil,
			})
			t.args = args{
				ctx: context.Background(),
			}
			t.fields = fields{
				expiryMargin:  expiryMargin,
				retryDelay:    time.Second,
				retryAttempts: 3,
				domain:        domain,
				athenzURL:     url,
				spVerifier:    dummySignedPolicyVerifier,
				client:        client,
				policyCache:   policyCache,
			}

			return t
		}(),
		func() (t test) {
			t.name = "success, on 304, return cached policy even if expired"

			// http response
			domain := "dummyDomain"
			expiryMargin := time.Hour
			_, client, url := createTestServer(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/domain/dummyDomain/signed_policy_data" {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				if r.Header.Get("If-None-Match") == `"dummyEtag"` {
					w.WriteHeader(http.StatusNotModified)
					return
				}

				w.WriteHeader(http.StatusInternalServerError)
			})

			// want objects
			expires := fastime.Now().Add(-expiryMargin)
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
				eTag:       `"dummyEtag"`,
				eTagExpiry: fastime.Now().Add(expiryMargin),
				sp:         sp,
				ctime:      fastime.Now(),
			}
			t.wantErrStr = ""

			// test input
			policyCache := unsafe.Pointer(t.wantPolicyCache)
			t.args = args{
				ctx: context.Background(),
			}
			t.fields = fields{
				expiryMargin:  expiryMargin,
				retryDelay:    time.Second,
				retryAttempts: 3,
				domain:        domain,
				athenzURL:     url,
				spVerifier:    dummySignedPolicyVerifier,
				client:        client,
				policyCache:   policyCache,
			}

			return t
		}(),
		func() (t test) {
			t.name = "fail, url error"

			// http response
			domain := "dummyDomain"

			// want objects
			t.want = nil
			t.wantPolicyCache = &taggedPolicy{ctime: fastime.Now()}
			t.wantErrStr = `create fetch policy request fail: parse "https:// /domain/dummyDomain/signed_policy_data": invalid character " " in host name`

			// test input
			policyCache := unsafe.Pointer(t.wantPolicyCache)
			t.args = args{
				ctx: context.Background(),
			}
			t.fields = fields{
				domain:      domain,
				athenzURL:   " ",
				policyCache: policyCache,
			}

			return t
		}(),
		func() (t test) {
			t.name = "fail, request error"

			// http response
			domain := "dummyDomain"
			_, client, _ := createTestServer(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			// want objects
			t.want = nil
			t.wantPolicyCache = &taggedPolicy{ctime: fastime.Now()}
			t.wantErrStr = `fetch policy HTTP request fail: Get "https://127.0.0.1/api/domain/dummyDomain/signed_policy_data": dial tcp 127.0.0.1:443: connect: connection refused`

			// test input
			policyCache := unsafe.Pointer(t.wantPolicyCache)
			t.args = args{
				ctx: context.Background(),
			}
			t.fields = fields{
				domain:      domain,
				athenzURL:   "127.0.0.1/api",
				client:      client,
				policyCache: policyCache,
			}

			return t
		}(),
		func() (t test) {
			t.name = "fail, server error"

			// http response
			domain := "dummyDomain"
			_, client, url := createTestServer(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			})

			// want objects
			t.want = nil
			t.wantPolicyCache = &taggedPolicy{ctime: fastime.Now()}
			t.wantErrStr = `fetch policy HTTP response != 200 OK: Error fetching athenz policy`

			// test input
			policyCache := unsafe.Pointer(t.wantPolicyCache)
			t.args = args{
				ctx: context.Background(),
			}
			t.fields = fields{
				domain:      domain,
				athenzURL:   url,
				client:      client,
				policyCache: policyCache,
			}

			return t
		}(),
		func() (t test) {
			t.name = "fail, policy decode error"

			// http response
			domain := "dummyDomain"
			_, client, url := createTestServer(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, err := w.Write([]byte(""))
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
			})

			// want objects
			t.want = nil
			t.wantPolicyCache = &taggedPolicy{ctime: fastime.Now()}
			t.wantErrStr = `policy decode fail: EOF`

			// test input
			policyCache := unsafe.Pointer(t.wantPolicyCache)
			t.args = args{
				ctx: context.Background(),
			}
			t.fields = fields{
				domain:      domain,
				athenzURL:   url,
				client:      client,
				policyCache: policyCache,
			}

			return t
		}(),
		func() (t test) {
			t.name = "fail, policy verify error"

			// http response
			domain := "dummyDomain"
			_, client, url := createTestServer(func(w http.ResponseWriter, r *http.Request) {
				_, err := w.Write([]byte("{}"))
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusOK)
			})

			// want objects
			t.want = nil
			t.wantPolicyCache = &taggedPolicy{ctime: fastime.Now()}
			t.wantErrStr = `invalid policy: dummy policy verify error`

			// test input
			policyCache := unsafe.Pointer(t.wantPolicyCache)
			t.args = args{
				ctx: context.Background(),
			}
			t.fields = fields{
				domain:    domain,
				athenzURL: url,
				spVerifier: func(sp *SignedPolicy) error {
					return errors.New("dummy policy verify error")
				},
				client:      client,
				policyCache: policyCache,
			}

			return t
		}(),
		func() (t test) {
			t.name = "fail, policy verify error, null expires"

			// http response
			domain := "dummyDomain"
			_, client, url := createTestServer(func(w http.ResponseWriter, r *http.Request) {
				_, err := w.Write([]byte(`{"signedPolicyData":{}}`))
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusOK)
			})

			// want objects
			t.want = nil
			t.wantPolicyCache = &taggedPolicy{ctime: fastime.Now()}
			t.wantErrStr = `invalid policy: policy without expiry`

			// test input
			policyCache := unsafe.Pointer(t.wantPolicyCache)
			t.args = args{
				ctx: context.Background(),
			}
			t.fields = fields{
				domain:      domain,
				athenzURL:   url,
				spVerifier:  dummySignedPolicyVerifier,
				client:      client,
				policyCache: policyCache,
			}

			return t
		}(),
		func() (t test) {
			t.name = "fail, policy verify error, invalid expires"

			// http response
			domain := "dummyDomain"
			_, client, url := createTestServer(func(w http.ResponseWriter, r *http.Request) {
				_, err := w.Write([]byte(`{"signedPolicyData":{"expires":"2099-12-31"}}`))
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusOK)
			})

			// want objects
			t.want = nil
			t.wantPolicyCache = &taggedPolicy{ctime: fastime.Now()}
			t.wantErrStr = `invalid policy: policy already expired at 0001-01-01 00:00:00 +0000 UTC`

			// test input
			policyCache := unsafe.Pointer(t.wantPolicyCache)
			t.args = args{
				ctx: context.Background(),
			}
			t.fields = fields{
				domain:      domain,
				athenzURL:   url,
				spVerifier:  dummySignedPolicyVerifier,
				client:      client,
				policyCache: policyCache,
			}

			return t
		}(),
		func() (t test) {
			t.name = "fail, policy verify error, expired policy"

			// http response
			domain := "dummyDomain"
			_, client, url := createTestServer(func(w http.ResponseWriter, r *http.Request) {
				_, err := w.Write([]byte(`{"signedPolicyData":{"expires":"2006-01-02T15:04:05.999Z"}}`))
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusOK)
			})

			// want objects
			t.want = nil
			t.wantPolicyCache = &taggedPolicy{ctime: fastime.Now()}
			t.wantErrStr = `invalid policy: policy already expired at 2006-01-02 15:04:05.999 +0000 UTC`

			// test input
			policyCache := unsafe.Pointer(t.wantPolicyCache)
			t.args = args{
				ctx: context.Background(),
			}
			t.fields = fields{
				domain:      domain,
				athenzURL:   url,
				spVerifier:  dummySignedPolicyVerifier,
				client:      client,
				policyCache: policyCache,
			}

			return t
		}(),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fetcher{
				expiryMargin:  tt.fields.expiryMargin,
				retryDelay:    tt.fields.retryDelay,
				retryAttempts: tt.fields.retryAttempts,
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
			gotPolicyCache := (*taggedPolicy)(f.policyCache)
			if err = compareTaggedPolicy(gotPolicyCache, tt.wantPolicyCache); err != nil {
				t.Errorf("fetcher.Fetch() policyCache = %v, want %v, error %v", gotPolicyCache, tt.wantPolicyCache, err)
				return
			}
		})
	}
}

func Test_fetcher_FetchWithRetry(t *testing.T) {
	type fields struct {
		expiryMargin  time.Duration
		retryDelay    time.Duration
		retryAttempts int
		domain        string
		athenzURL     string
		spVerifier    SignedPolicyVerifier
		client        *http.Client
		policyCache   unsafe.Pointer
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
		cmpTP           func(a, b *taggedPolicy) error
	}
	createTestServer := func(hf http.HandlerFunc) (*httptest.Server, *http.Client, string) {
		srv := httptest.NewTLSServer(hf)
		return srv, srv.Client(), strings.Replace(srv.URL, "https://", "", 1)
	}
	compareTaggedPolicy := func(a, b *taggedPolicy) error {
		if a == b {
			return nil
		}
		if a.eTag != b.eTag {
			return errors.New("eTag")
		}
		if a.eTagExpiry != b.eTagExpiry {
			return errors.New("eTagExpiry")
		}
		if !reflect.DeepEqual(a.sp, b.sp) {
			return errors.New("sp")
		}
		if time.Duration(math.Abs(float64(a.ctime.Sub(b.ctime)))) > time.Second {
			return errors.New("ctime")
		}
		return nil
	}
	tests := []test{
		func() (t test) {
			t.name = "success, no retry"
			var requestCount uint32

			// HTTP response
			expiryMargin := time.Hour
			retryDelay := time.Minute
			retryAttempts := 0
			keyID := "keyId"
			_, client, url := createTestServer(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Add("ETag", fmt.Sprintf(`"dummyEtag%d"`, atomic.AddUint32(&requestCount, 1)))
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				_, err := w.Write([]byte(fmt.Sprintf(`{"keyId":"%v","signedPolicyData":{"expires":""}}`, keyID)))
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusOK)
			})

			// want objects
			sp := &SignedPolicy{
				util.DomainSignedPolicyData{
					KeyId:     "keyId",
					Signature: "",
					SignedPolicyData: &util.SignedPolicyData{
						Expires:      &rdl.Timestamp{},
						Modified:     nil,
						PolicyData:   nil,
						ZmsKeyId:     "",
						ZmsSignature: "",
					},
				},
			}
			t.want = sp
			t.wantPolicyCache = &taggedPolicy{
				eTag:       `"dummyEtag1"`,
				eTagExpiry: time.Time{}.Add(-expiryMargin),
				sp:         sp,
				ctime:      fastime.Now(),
			}
			t.wantErrStr = ""
			t.cmpTP = compareTaggedPolicy

			// test input
			policyCache := unsafe.Pointer(t.wantPolicyCache)
			t.args = args{
				ctx: context.Background(),
			}
			t.fields = fields{
				expiryMargin:  expiryMargin,
				retryDelay:    retryDelay,
				retryAttempts: retryAttempts,
				domain:        "dummyDomain",
				athenzURL:     url,
				spVerifier:    func(sp *SignedPolicy) error { return nil },
				client:        client,
				policyCache:   policyCache,
			}

			return t
		}(),
		func() (t test) {
			t.name = "success, after retry"
			var requestCount uint32

			// HTTP response
			expiryMargin := time.Hour
			retryDelay := 100 * time.Millisecond
			retryAttempts := 2
			keyID := "keyId"
			_, client, url := createTestServer(func(w http.ResponseWriter, r *http.Request) {
				rc := atomic.AddUint32(&requestCount, 1)
				if rc < 3 {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				w.Header().Add("ETag", fmt.Sprintf(`"dummyEtag%d"`, rc))
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				_, err := w.Write([]byte(fmt.Sprintf(`{"keyId":"%v","signedPolicyData":{"expires":""}}`, keyID)))
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusOK)
			})

			// want objects
			sp := &SignedPolicy{
				util.DomainSignedPolicyData{
					KeyId:     "keyId",
					Signature: "",
					SignedPolicyData: &util.SignedPolicyData{
						Expires:      &rdl.Timestamp{},
						Modified:     nil,
						PolicyData:   nil,
						ZmsKeyId:     "",
						ZmsSignature: "",
					},
				},
			}
			t.want = sp
			t.wantPolicyCache = &taggedPolicy{
				eTag:       `"dummyEtag3"`,
				eTagExpiry: time.Time{}.Add(-expiryMargin),
				sp:         sp,
				ctime:      fastime.Now(),
			}
			t.wantErrStr = ""
			t.cmpTP = func(a, b *taggedPolicy) error {
				err := compareTaggedPolicy(a, b)
				if err != nil {
					return err
				}

				// check retry interval
				diff := a.ctime.Sub(b.ctime)
				if diff < retryDelay*time.Duration(retryAttempts) || diff > retryDelay*time.Duration(retryAttempts+1) {
					return errors.New("retry interval not working")
				}
				return nil
			}

			// test input
			policyCache := unsafe.Pointer(t.wantPolicyCache)
			t.args = args{
				ctx: context.Background(),
			}
			t.fields = fields{
				expiryMargin:  expiryMargin,
				retryDelay:    retryDelay,
				retryAttempts: retryAttempts,
				domain:        "dummyDomain",
				athenzURL:     url,
				spVerifier:    func(sp *SignedPolicy) error { return nil },
				client:        client,
				policyCache:   policyCache,
			}

			return t
		}(),
		func() (t test) {
			t.name = "all fail, no policy cache"

			// HTTP response
			expiryMargin := time.Hour
			retryDelay := time.Millisecond
			retryAttempts := 2
			_, client, url := createTestServer(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			})

			// want objects
			t.want = nil
			t.wantPolicyCache = nil
			t.wantErrStr = "no policy cache: max. retry count excess: fetch policy HTTP response != 200 OK: Error fetching athenz policy"
			t.cmpTP = compareTaggedPolicy

			// test input
			t.args = args{
				ctx: context.Background(),
			}
			t.fields = fields{
				expiryMargin:  expiryMargin,
				retryDelay:    retryDelay,
				retryAttempts: retryAttempts,
				domain:        "dummyDomain",
				athenzURL:     url,
				spVerifier:    func(sp *SignedPolicy) error { return nil },
				client:        client,
				// policyCache:   policyCache,
			}

			return t
		}(),
		func() (t test) {
			t.name = "all fail, return cached policy"

			// HTTP response
			expiryMargin := time.Hour
			retryDelay := time.Millisecond
			retryAttempts := 2
			_, client, url := createTestServer(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			})

			// want objects
			sp := &SignedPolicy{
				util.DomainSignedPolicyData{
					KeyId:     "keyId",
					Signature: "",
					SignedPolicyData: &util.SignedPolicyData{
						Expires:      &rdl.Timestamp{},
						Modified:     nil,
						PolicyData:   nil,
						ZmsKeyId:     "",
						ZmsSignature: "",
					},
				},
			}
			t.want = sp
			t.wantPolicyCache = &taggedPolicy{
				eTag:       `"dummyEtag"`,
				eTagExpiry: time.Time{}.Add(-expiryMargin),
				sp:         sp,
				ctime:      fastime.Now(),
			}
			t.wantErrStr = "max. retry count excess: fetch policy HTTP response != 200 OK: Error fetching athenz policy"
			t.cmpTP = compareTaggedPolicy

			// test input
			policyCache := unsafe.Pointer(t.wantPolicyCache)
			t.args = args{
				ctx: context.Background(),
			}
			t.fields = fields{
				expiryMargin:  expiryMargin,
				retryDelay:    retryDelay,
				retryAttempts: retryAttempts,
				domain:        "dummyDomain",
				athenzURL:     url,
				spVerifier:    func(sp *SignedPolicy) error { return nil },
				client:        client,
				policyCache:   policyCache,
			}

			return t
		}(),
		func() (t test) {
			t.name = "retryAttempts < 0"

			// HTTP response
			expiryMargin := time.Hour
			retryDelay := time.Millisecond
			retryAttempts := -1

			// want objects
			sp := &SignedPolicy{
				util.DomainSignedPolicyData{
					KeyId:     "keyId",
					Signature: "",
					SignedPolicyData: &util.SignedPolicyData{
						Expires:      &rdl.Timestamp{},
						Modified:     nil,
						PolicyData:   nil,
						ZmsKeyId:     "",
						ZmsSignature: "",
					},
				},
			}
			t.want = sp
			t.wantPolicyCache = &taggedPolicy{
				eTag:       `"dummyEtag"`,
				eTagExpiry: time.Time{}.Add(-expiryMargin),
				sp:         sp,
				ctime:      fastime.Now(),
			}
			t.wantErrStr = "max. retry count excess: retryAttempts -1"
			t.cmpTP = compareTaggedPolicy

			// test input
			policyCache := unsafe.Pointer(t.wantPolicyCache)
			t.args = args{
				ctx: context.Background(),
			}
			t.fields = fields{
				expiryMargin:  expiryMargin,
				retryDelay:    retryDelay,
				retryAttempts: retryAttempts,
				domain:        "dummyDomain",
				spVerifier:    func(sp *SignedPolicy) error { return nil },
				policyCache:   policyCache,
			}

			return t
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fetcher{
				expiryMargin:  tt.fields.expiryMargin,
				retryDelay:    tt.fields.retryDelay,
				retryAttempts: tt.fields.retryAttempts,
				domain:        tt.fields.domain,
				athenzURL:     tt.fields.athenzURL,
				spVerifier:    tt.fields.spVerifier,
				client:        tt.fields.client,
				policyCache:   tt.fields.policyCache,
			}
			got, err := f.FetchWithRetry(tt.args.ctx)
			if (err == nil && tt.wantErrStr != "") || (err != nil && err.Error() != tt.wantErrStr) {
				t.Errorf("fetcher.FetchWithRetry() error = %v, wantErr %v", err, tt.wantErrStr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("fetcher.FetchWithRetry() = %v, want %v", got, tt.want)
			}
			gotPolicyCache := (*taggedPolicy)(f.policyCache)
			if err = tt.cmpTP(gotPolicyCache, tt.wantPolicyCache); err != nil {
				t.Errorf("fetcher.FetchWithRetry() policyCache = %v, want %v, error %v", gotPolicyCache, tt.wantPolicyCache, err)
				return
			}
		})
	}

}

func Test_taggedPolicy_String(t *testing.T) {
	type fields struct {
		eTag       string
		eTagExpiry time.Time
		sp         *SignedPolicy
		ctime      time.Time
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name:   "default value",
			fields: fields{},
			want:   `{ ctime: 0001-01-01 00:00:00 +0000 UTC, eTag: , eTagExpiry: 0001-01-01 00:00:00 +0000 UTC, sp.domain:  }`,
		},
		{
			name: "custom value",
			fields: fields{
				eTag:       `"eTag"`,
				eTagExpiry: time.Unix(1567454350, 167000000),
				ctime:      time.Unix(1566454350, 167000000),
				// sp: &SignedPolicy{},
			},
			want: `{ ctime: 2019-08-22 06:12:30.167 +0000 UTC, eTag: "eTag", eTagExpiry: 2019-09-02 19:59:10.167 +0000 UTC, sp.domain:  }`,
		},
		{
			name: "policy without data",
			fields: fields{
				eTag: `"eTag"`,
				sp: &SignedPolicy{
					DomainSignedPolicyData: util.DomainSignedPolicyData{
						SignedPolicyData: &util.SignedPolicyData{
							PolicyData: nil,
						},
					},
				},
			},
			want: `{ ctime: 0001-01-01 00:00:00 +0000 UTC, eTag: "eTag", eTagExpiry: 0001-01-01 00:00:00 +0000 UTC, sp.domain:  }`,
		},
		{
			name: "policy with data",
			fields: fields{
				eTag: `"eTag"`,
				sp: &SignedPolicy{
					DomainSignedPolicyData: util.DomainSignedPolicyData{
						SignedPolicyData: &util.SignedPolicyData{
							PolicyData: &util.PolicyData{Domain: "domain"},
						},
					},
				},
			},
			want: `{ ctime: 0001-01-01 00:00:00 +0000 UTC, eTag: "eTag", eTagExpiry: 0001-01-01 00:00:00 +0000 UTC, sp.domain: domain }`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tp := &taggedPolicy{
				eTag:       tt.fields.eTag,
				eTagExpiry: tt.fields.eTagExpiry,
				sp:         tt.fields.sp,
				ctime:      tt.fields.ctime,
			}
			if got := tp.String(); got != tt.want {
				t.Errorf("taggedPolicy.String() = %v, want %v", got, tt.want)
			}
		})
	}
}
