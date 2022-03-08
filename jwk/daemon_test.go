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
package jwk

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"
)

func TestNew(t *testing.T) {
	type args struct {
		opts []Option
	}
	tests := []struct {
		name    string
		args    args
		want    Daemon
		wantErr bool
	}{
		{
			name: "New daemon success",
			args: args{
				opts: []Option{
					WithAthenzJwksURL("www.dummy.com"),
				},
			},
			want: &jwkd{
				athenzJwksURL: "https://www.dummy.com/oauth2/keys?rfc=true",
				refreshPeriod: time.Hour * 24,
				retryDelay:    time.Minute,
				client:        http.DefaultClient,
				keys:          &sync.Map{},
			},
		},
		{
			name: "New daemon fail",
			args: args{
				opts: []Option{
					WithRefreshPeriod("dummy"),
				},
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
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_jwkd_Start(t *testing.T) {
	type fields struct {
		athenzJwksURL string
		refreshPeriod time.Duration
		retryDelay    time.Duration
		client        *http.Client
		keys          *sync.Map
	}
	type args struct {
		ctx context.Context
	}
	type test struct {
		name      string
		fields    fields
		args      args
		checkFunc func(*jwkd, <-chan error) error
		afterFunc func()
	}
	tests := []test{
		func() test {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(500)
			}))
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			return test{
				name: "canceled context",
				fields: fields{
					athenzJwksURL: srv.URL,
					refreshPeriod: time.Millisecond * 10,
					retryDelay:    time.Millisecond,
					client:        srv.Client(),
					keys:          &sync.Map{},
				},
				args: args{
					ctx: ctx,
				},
				checkFunc: func(j *jwkd, ch <-chan error) error {
					err := <-ch
					wantErr := context.Canceled
					if err != wantErr {
						return fmt.Errorf("got: %v, want: %v", err, wantErr)
					}
					for err = range ch {
						if err != nil {
							return err
						}
					}

					if k, _ := j.keys.Load(j.athenzJwksURL); k != nil {
						return errors.New("keys updated")
					}

					return nil
				},
			}
		}(),
		func() test {
			k := `{
"e":"AQAB",
"kty":"RSA",
"n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
}`
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, err := w.Write([]byte(k))
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
			}))
			ctx, cancel := context.WithCancel(context.Background())

			return test{
				name: "Start success",
				fields: fields{
					athenzJwksURL: srv.URL,
					refreshPeriod: time.Millisecond * 10,
					retryDelay:    time.Millisecond,
					client:        srv.Client(),
					keys:          &sync.Map{},
				},
				args: args{
					ctx: ctx,
				},
				checkFunc: func(j *jwkd, ch <-chan error) error {
					time.Sleep(time.Millisecond * 200)
					cancel()
					if k, _ := j.keys.Load(j.athenzJwksURL); k == nil {
						return errors.New("cannot update keys")
					}

					return nil
				},
				afterFunc: func() {
					cancel()
				},
			}
		}(),
		func() test {
			i := 1
			k := `{
"e":"AQAB",
"kty":"RSA",
"kid" :"%s",
"n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
}`
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, err := w.Write([]byte(fmt.Sprintf(k, i)))
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				i = i + 1
			}))
			ctx, cancel := context.WithCancel(context.Background())

			return test{
				name: "Start can update",
				fields: fields{
					athenzJwksURL: srv.URL,
					refreshPeriod: time.Millisecond * 10,
					retryDelay:    time.Millisecond,
					client:        srv.Client(),
					keys:          &sync.Map{},
				},
				args: args{
					ctx: ctx,
				},
				checkFunc: func(j *jwkd, ch <-chan error) error {
					time.Sleep(time.Millisecond * 100)
					k1, _ := j.keys.Load(j.athenzJwksURL)
					if k1 == nil {
						return errors.New("cannot update keys")
					}

					time.Sleep(time.Millisecond * 30)
					cancel()

					k2, _ := j.keys.Load(j.athenzJwksURL)
					if k2 == nil {
						return errors.New("cannot update keys")
					}

					k1k, _ := k1.(jwk.Set).Get(0)
					k2k, _ := k2.(jwk.Set).Get(0)
					if k1k.KeyID() == k2k.KeyID() {
						return errors.Errorf("key do not update after it starts, k1.KeyID: %v equals k2.KeyID: %v", k1k.KeyID(), k2k.KeyID())
					}

					return nil
				},
				afterFunc: func() {
					cancel()
				},
			}
		}(),
		func() test {
			i := 1
			k := `{
"e":"AQAB",
"kty":"RSA",
"n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
}`
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if i < 3 {
					i++
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusOK)
				_, err := w.Write([]byte(k))
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				i = i + 1
			}))
			ctx, cancel := context.WithCancel(context.Background())

			return test{
				name: "Start retry update",
				fields: fields{
					athenzJwksURL: srv.URL,
					refreshPeriod: time.Millisecond * 10,
					retryDelay:    time.Millisecond,
					client:        srv.Client(),
					keys:          &sync.Map{},
				},
				args: args{
					ctx: ctx,
				},
				checkFunc: func(j *jwkd, ch <-chan error) error {
					time.Sleep(time.Millisecond * 100)
					if k, _ := j.keys.Load(j.athenzJwksURL); k == nil {
						return errors.New("cannot update keys")
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
			j := &jwkd{
				athenzJwksURL: tt.fields.athenzJwksURL,
				refreshPeriod: tt.fields.refreshPeriod,
				retryDelay:    tt.fields.retryDelay,
				client:        tt.fields.client,
				keys:          tt.fields.keys,
			}
			got := j.Start(tt.args.ctx)
			if tt.checkFunc != nil {
				if err := tt.checkFunc(j, got); err != nil {
					t.Errorf("jwkd.Start() error = %v", err)
				}
			}
		})
	}
}

func Test_jwkd_Update(t *testing.T) {
	type fields struct {
		athenzJwksURL string
		urls          []string
		refreshPeriod time.Duration
		retryDelay    time.Duration
		client        *http.Client
		keys          *sync.Map
	}
	type args struct {
		ctx context.Context
	}
	type test struct {
		name       string
		fields     fields
		args       args
		checkFunc  func(*jwkd) error
		wantErr    bool
		wantErrStr string
	}
	tests := []test{
		func() test {
			k := `{
"e":"AQAB",
"kty":"RSA",
"n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
}`
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, err := w.Write([]byte(k))
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
			}))

			return test{
				name: "Update success without urls",
				fields: fields{
					athenzJwksURL: srv.URL,
					client:        srv.Client(),
					keys:          &sync.Map{},
				},
				args: args{
					ctx: context.Background(),
				},
				checkFunc: func(j *jwkd) error {
					val, _ := j.keys.Load(j.athenzJwksURL)
					if val == nil {
						return errors.New("keys is empty")
					}

					vk, _ := val.(jwk.Set).Get(0)
					got := vk.KeyType()
					if got != jwa.RSA {
						return errors.Errorf("Unexpected key type: %v", got)
					}
					return nil
				},
			}
		}(),
		func() test {
			k := `{
"e":"AQAB",
"kty":"RSA",
"n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
}`
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, err := w.Write([]byte(k))
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
			}))

			return test{
				name: "Update success with urls",
				fields: fields{
					athenzJwksURL: srv.URL,
					urls:          []string{srv.URL + "/urls"},
					client:        srv.Client(),
					keys:          &sync.Map{},
				},
				args: args{
					ctx: context.Background(),
				},
				checkFunc: func(j *jwkd) error {
					// key from athenzJwksURL
					val, ok := j.keys.Load(j.athenzJwksURL)
					if !ok {
						return errors.New("athenz keys is empty")
					}

					vk, _ := val.(jwk.Set).Get(0)
					got := vk.KeyType()
					if got != jwa.RSA {
						return errors.Errorf("Unexpected key type from athenz: %v", got)
					}

					// key from urls
					val, ok = j.keys.Load(j.urls[0])
					if !ok {
						return errors.New("urls keys is empty")
					}

					vk, _ = val.(jwk.Set).Get(0)
					got = vk.KeyType()
					if got != jwa.RSA {
						return errors.Errorf("Unexpected key type from urls: %v", got)
					}
					return nil
				},
			}
		}(),
		func() test {
			k := `{
"e":"AQAB",
"kty":"dummy",
"n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
}`
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, err := w.Write([]byte(k))
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
			}))

			return test{
				name: "Update fail without urls",
				fields: fields{
					athenzJwksURL: srv.URL,
					client:        srv.Client(),
					keys:          &sync.Map{},
				},
				args: args{
					ctx: context.Background(),
				},
				checkFunc: func(j *jwkd) error {
					if _, ok := j.keys.Load(j.athenzJwksURL); ok {
						return errors.Errorf("ok expecetd false")
					}
					return nil
				},
				wantErr:    true,
				wantErrStr: fmt.Sprintf("Failed to fetch the JWK Set from these URLs: %s", []string{srv.URL}),
			}
		}(),
		func() test {
			validKey := `{
"e":"AQAB",
"kty":"RSA",
"n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
}`
			invalidKey := `{
"e":"AQAB",
"kty":"dummy",
"n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
}`
			// frag for distinguish between the keys to be output.
			isFirst := true
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				var err error
				// Only the first time returns a valid key.
				if isFirst {
					_, err = w.Write([]byte(validKey))
				} else {
					_, err = w.Write([]byte(invalidKey))
				}
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				isFirst = false
			}))

			return test{
				name: "Update fail with urls, athenz key success, urls key fail",
				fields: fields{
					athenzJwksURL: srv.URL + "/success",
					urls:          []string{srv.URL + "/invalid"},
					client:        srv.Client(),
					keys:          &sync.Map{},
				},
				args: args{
					ctx: context.Background(),
				},
				checkFunc: func(j *jwkd) error {
					// key from athenz, expect success
					val, ok := j.keys.Load(j.athenzJwksURL)
					if !ok {
						return errors.New("athenz keys is empty")
					}
					vk, _ := val.(jwk.Set).Get(0)
					got := vk.KeyType()
					if got != jwa.RSA {
						return errors.Errorf("Unexpected key type from athenz: %v", got)
					}
					// key from urls, expect fail
					if _, ok := j.keys.Load(j.urls[0]); ok {
						return errors.Errorf("ok from urls expecetd false")
					}
					return nil
				},
				wantErr:    true,
				wantErrStr: fmt.Sprintf("Failed to fetch the JWK Set from these URLs: %s", []string{srv.URL + "/invalid"}),
			}
		}(),
		func() test {
			validKey := `{
"e":"AQAB",
"kty":"RSA",
"n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
}`
			invalidKey := `{
"e":"AQAB",
"kty":"dummy",
"n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
}`
			// frag for distinguish between the keys to be output.
			isFirst := true
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				var err error
				// Only the first time returns a invalid key.
				if isFirst {
					_, err = w.Write([]byte(invalidKey))
				} else {
					_, err = w.Write([]byte(validKey))
				}
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				isFirst = false
			}))

			return test{
				name: "Update fail with urls, athenz key fail, urls key success",
				fields: fields{
					athenzJwksURL: srv.URL + "/invalid",
					urls:          []string{srv.URL + "/success1", srv.URL + "/success2"},
					client:        srv.Client(),
					keys:          &sync.Map{},
				},
				args: args{
					ctx: context.Background(),
				},
				checkFunc: func(j *jwkd) error {
					// key from athenz(/invalid), expect fail
					if _, ok := j.keys.Load(j.athenzJwksURL); ok {
						return errors.Errorf("ok from athenz expecetd false")
					}
					// key from urls (/success1), expect success
					val1, ok := j.keys.Load(j.urls[0])
					if !ok {
						return errors.New("athenz keys is empty")
					}
					v1k, _ := val1.(jwk.Set).Get(0)
					got1 := v1k.KeyType()
					if got1 != jwa.RSA {
						return errors.Errorf("Unexpected key type from urls: %v", got1)
					}
					// key from urls (/success2), expect success
					val2, ok := j.keys.Load(j.urls[1])
					if !ok {
						return errors.New("athenz keys is empty")
					}
					v2k, _ := val2.(jwk.Set).Get(0)
					got2 := v2k.KeyType()
					if got2 != jwa.RSA {
						return errors.Errorf("Unexpected key type from urls: %v", got2)
					}
					return nil
				},
				wantErr:    true,
				wantErrStr: fmt.Sprintf("Failed to fetch the JWK Set from these URLs: %s", []string{srv.URL + "/invalid"}),
			}
		}(),
		func() test {
			k := `{
"e":"AQAB",
"kty":"dummy",
"n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
}`
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, err := w.Write([]byte(k))
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
			}))

			return test{
				name: "Update fail with urls, athenz key fail, urls key fail",
				fields: fields{
					athenzJwksURL: srv.URL + "/invalid1",
					urls:          []string{srv.URL + "/invalid2", srv.URL + "/invalid3"},
					client:        srv.Client(),
					keys:          &sync.Map{},
				},
				args: args{
					ctx: context.Background(),
				},
				checkFunc: func(j *jwkd) error {
					// key from athenz(/invalid), expect fail
					if _, ok := j.keys.Load(j.athenzJwksURL); ok {
						return errors.Errorf("ok from athenz expecetd false")
					}
					// key from urls (/success1), expect success
					if _, ok := j.keys.Load(j.urls[0]); ok {
						return errors.Errorf("ok from athenz expecetd false")
					}
					// key from urls (/success2), expect success
					if _, ok := j.keys.Load(j.urls[1]); ok {
						return errors.Errorf("ok from athenz expecetd false")
					}
					return nil
				},
				wantErr:    true,
				wantErrStr: fmt.Sprintf("Failed to fetch the JWK Set from these URLs: %s", []string{srv.URL + "/invalid1", srv.URL + "/invalid2", srv.URL + "/invalid3"}),
			}
		}(),
		func() test {
			k := `{
"e":"AQAB",
"kty":"RSA",
"n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
}`
			var callCount int
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, err := w.Write([]byte(k))
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				callCount++
			}))

			return test{
				name: "Remove duplicate ahtenz url",
				fields: fields{
					// athenz * 2, other * 1
					athenzJwksURL: srv.URL + "/athenz",
					urls:          []string{srv.URL + "/athenz", srv.URL + "/other"},
					client:        srv.Client(),
					keys:          &sync.Map{},
				},
				args: args{
					ctx: context.Background(),
				},
				checkFunc: func(j *jwkd) error {
					// key from athenzJwksURL
					val, ok := j.keys.Load(j.athenzJwksURL)
					if !ok {
						return errors.New("athenz keys is empty")
					}

					vk, _ := val.(jwk.Set).Get(0)
					got := vk.KeyType()
					if got != jwa.RSA {
						return errors.Errorf("Unexpected key type from athenz: %v", got)
					}

					// key from urls (/athenz)
					val, ok = j.keys.Load(j.urls[0])
					if !ok {
						return errors.New("urls keys is empty")
					}

					vk, _ = val.(jwk.Set).Get(0)
					got = vk.KeyType()
					if got != jwa.RSA {
						return errors.Errorf("Unexpected key type from urls: %v", got)
					}

					// key from urls (/other)
					val, ok = j.keys.Load(j.urls[1])
					if !ok {
						return errors.New("urls keys is empty")
					}

					vk, _ = val.(jwk.Set).Get(0)
					got = vk.KeyType()
					if got != jwa.RSA {
						return errors.Errorf("Unexpected key type from urls: %v", got)
					}

					// count check
					if callCount != 2 {
						return errors.Errorf("Unexpected callCount: %v", callCount)
					}
					return nil
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := &jwkd{
				athenzJwksURL: tt.fields.athenzJwksURL,
				urls:          tt.fields.urls,
				refreshPeriod: tt.fields.refreshPeriod,
				retryDelay:    tt.fields.retryDelay,
				client:        tt.fields.client,
				keys:          tt.fields.keys,
			}
			err := j.Update(tt.args.ctx)
			if tt.wantErr {
				if err.Error() != tt.wantErrStr {
					t.Errorf("jwkd.Update() error = %v, wantErrStr %v", err, tt.wantErrStr)
				}
			}
			if tt.checkFunc != nil {
				if err := tt.checkFunc(j); err != nil {
					t.Errorf("jwkd.Update() error = %v", err)
				}
			}
		})
	}
}

func Test_jwkd_GetProvider(t *testing.T) {
	type fields struct {
		athenzJwksURL string
		refreshPeriod time.Duration
		retryDelay    time.Duration
		client        *http.Client
		keys          *sync.Map
	}
	tests := []struct {
		name      string
		fields    fields
		checkFunc func(Provider) error
	}{
		{
			name: "get success",
			checkFunc: func(p Provider) error {
				if p == nil {
					return errors.New("GetProvider return nil")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := &jwkd{
				athenzJwksURL: tt.fields.athenzJwksURL,
				refreshPeriod: tt.fields.refreshPeriod,
				retryDelay:    tt.fields.retryDelay,
				client:        tt.fields.client,
				keys:          tt.fields.keys,
			}
			got := j.GetProvider()
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("jwkd.GetProvider() err %v", err)
			}
		})
	}
}

func Test_jwkd_getKey(t *testing.T) {
	type fields struct {
		athenzJwksURL string
		refreshPeriod time.Duration
		retryDelay    time.Duration
		client        *http.Client
		keys          *sync.Map
	}
	type args struct {
		keyID     string
		jwkSetURL string
	}
	type test struct {
		name   string
		fields fields
		args   args
		want   interface{}
	}
	genKey := func() *rsa.PrivateKey {
		k, _ := rsa.GenerateKey(rand.Reader, 2048)
		return k
	}
	newKey := func(k interface{}, keyID string) jwk.Key {
		jwkKey, _ := jwk.New(k)
		err := jwkKey.Set(jwk.KeyIDKey, keyID)
		if err != nil {
			t.Errorf("jwkd.getKey() setup error = %v", err)
		}
		return jwkKey
	}
	tests := []test{
		func() test {
			rsaKey := genKey()
			set := jwk.NewSet()
			set.Add(newKey(rsaKey, "dummyID"))
			key := sync.Map{}
			key.Store("dummy.com", set)

			return test{
				name: "get key success",
				fields: fields{
					keys:          &key,
					athenzJwksURL: "dummy.com",
				},
				args: args{
					keyID:     "dummyID",
					jwkSetURL: "",
				},
				want: rsaKey,
			}
		}(),
		func() test {
			rsaKey := genKey()
			set := jwk.NewSet()
			set.Add(newKey(rsaKey, "dummyID"))
			key := sync.Map{}
			key.Store("dummy.com", set)

			return test{
				name: "get key not found",
				fields: fields{
					keys:          &key,
					athenzJwksURL: "dummy.com",
				},
				args: args{
					keyID:     "not exists",
					jwkSetURL: "",
				},
				want: nil,
			}
		}(),
		func() test {
			rsaKey := genKey()
			set := jwk.NewSet()
			set.Add(newKey(rsaKey, ""))
			key := sync.Map{}
			key.Store("dummy.com", set)

			return test{
				name: "get key id empty return nil",
				fields: fields{
					keys:          &key,
					athenzJwksURL: "dummy.com",
				},
				args: args{
					keyID:     "",
					jwkSetURL: "",
				},
				want: nil,
			}
		}(),
		func() test {
			rsaKey := genKey()
			set := jwk.NewSet()
			set.Add(newKey(rsaKey, ""))
			key := sync.Map{}
			key.Store("dummy.com", set)

			return test{
				name: "get key id empty, but jwkSetURL is not empty, return nil",
				fields: fields{
					keys:          &key,
					athenzJwksURL: "dummy.com",
				},
				args: args{
					keyID:     "",
					jwkSetURL: "dummy2.com",
				},
				want: nil,
			}
		}(),
		func() test {
			rsaKey1 := genKey()
			rsaKey2 := genKey()
			rsaKey3 := genKey()
			set := jwk.NewSet()
			set.Add(newKey(rsaKey1, "dummyID1"))
			set.Add(newKey(rsaKey2, "dummyID2"))
			set.Add(newKey(rsaKey3, "dummyID3"))
			key := sync.Map{}
			key.Store("dummy.com", set)

			return test{
				name: "get key success from multiple key",
				fields: fields{
					keys:          &key,
					athenzJwksURL: "dummy.com",
				},
				args: args{
					keyID:     "dummyID2",
					jwkSetURL: "",
				},
				want: rsaKey2,
			}
		}(),
		func() test {
			ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Errorf("ecdsa.GenerateKey: %s", err.Error())
			}
			set := jwk.NewSet()
			set.Add(newKey(ecKey, "ecKeyID"))
			key := sync.Map{}
			key.Store("dummy.com", set)

			return test{
				name: "get EC private key success",
				fields: fields{
					keys:          &key,
					athenzJwksURL: "dummy.com",
				},
				args: args{
					keyID:     "ecKeyID",
					jwkSetURL: "",
				},
				want: ecKey,
			}
		}(),
		func() test {
			ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			ecPubKey := ecKey.Public()
			if err != nil {
				t.Errorf("ecdsa.GenerateKey: %s", err.Error())
			}
			set := jwk.NewSet()
			set.Add(newKey(ecPubKey, "ecPubKeyID"))
			key := sync.Map{}
			key.Store("dummy.com", set)

			return test{
				name: "get EC public key success",
				fields: fields{
					keys:          &key,
					athenzJwksURL: "dummy.com",
				},
				args: args{
					keyID: "ecPubKeyID",
				},
				want: ecPubKey,
			}
		}(),
		func() test {
			rsaPubKey := genKey().Public()
			set := jwk.NewSet()
			set.Add(newKey(rsaPubKey, "rsaPubKeyID"))
			key := sync.Map{}
			key.Store("dummy.com", set)

			return test{
				name: "get RSA public key success",
				fields: fields{
					keys:          &key,
					athenzJwksURL: "dummy.com",
				},
				args: args{
					keyID: "rsaPubKeyID",
				},
				want: rsaPubKey,
			}
		}(),
		func() test {
			rsaKey := genKey()
			set := jwk.NewSet()
			set.Add(newKey(rsaKey, "dummyID"))
			key := sync.Map{}
			key.Store("dummy2.com", set)

			return test{
				name: "get key success jwkSetURL",
				fields: fields{
					keys:          &key,
					athenzJwksURL: "dummy.com",
				},
				args: args{
					keyID:     "dummyID",
					jwkSetURL: "dummy2.com",
				},
				want: rsaKey,
			}
		}(),
		func() test {
			rsaKey1 := genKey()
			set1 := jwk.NewSet()
			set1.Add(newKey(rsaKey1, "dummyID"))
			rsaKey2 := genKey()
			set2 := jwk.NewSet()
			set2.Add(newKey(rsaKey2, "dummyID"))
			key := sync.Map{}
			key.Store("dummy1.com", set1)
			key.Store("dummy2.com", set2)

			return test{
				name: "get key fail, no exist jwkSetURL",
				fields: fields{
					keys:          &key,
					athenzJwksURL: "dummy1.com",
				},
				args: args{
					keyID:     "dummyID",
					jwkSetURL: "dummy-not-found.com",
				},
				want: nil,
			}
		}(),
		func() test {
			rsaKey := genKey()
			set := jwk.NewSet()
			set.Add(newKey(rsaKey, "dummyID"))
			key := sync.Map{}
			key.Store("dummy2.com", set)

			return test{
				name: "get key not found in jwkSetURL",
				fields: fields{
					keys:          &key,
					athenzJwksURL: "dummy1.com",
				},
				args: args{
					keyID:     "not exists",
					jwkSetURL: "dummy2.com",
				},
				want: nil,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := &jwkd{
				athenzJwksURL: tt.fields.athenzJwksURL,
				refreshPeriod: tt.fields.refreshPeriod,
				retryDelay:    tt.fields.retryDelay,
				client:        tt.fields.client,
				keys:          tt.fields.keys,
			}
			if got := j.getKey(tt.args.keyID, tt.args.jwkSetURL); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("jwkd.getKey() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func Test_jwkd_isContain(t *testing.T) {
	type args struct {
		targets []string
		key     string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "return true",
			args: args{
				targets: []string{"dummyA", "dummyB", "dummyC"},
				key:     "dummyB",
			},
			want: true,
		},
		{
			name: "return false",
			args: args{
				targets: []string{"dummyA", "dummyB", "dummyC"},
				key:     "dummyD",
			},
			want: false,
		},
		{
			name: "use nil in targets",
			args: args{
				targets: nil,
				key:     "dummyD",
			},
			want: false,
		},
		{
			name: "use empty in key",
			args: args{
				targets: []string{"dummyA", "dummyB", "dummyC"},
				key:     "",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isContain(tt.args.targets, tt.args.key); got != tt.want {
				t.Errorf("jwkd.isContain() = %v, want %v", got, tt.want)
			}
		})
	}
}
