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
	"strings"
	"sync/atomic"
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
					WithAthenzURL("www.dummy.com"),
				},
			},
			want: &jwkd{
				athenzURL:     "www.dummy.com",
				refreshPeriod: time.Hour * 24,
				retryDelay:    time.Minute,
				client:        http.DefaultClient,
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
		athenzURL     string
		refreshPeriod time.Duration
		retryDelay    time.Duration
		client        *http.Client
		keys          atomic.Value
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
					athenzURL:     strings.Replace(srv.URL, "https://", "", 1),
					refreshPeriod: time.Millisecond * 10,
					retryDelay:    time.Millisecond,
					client:        srv.Client(),
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

					if k := j.keys.Load(); k != nil {
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
					athenzURL:     strings.Replace(srv.URL, "https://", "", 1),
					refreshPeriod: time.Millisecond * 10,
					retryDelay:    time.Millisecond,
					client:        srv.Client(),
				},
				args: args{
					ctx: ctx,
				},
				checkFunc: func(j *jwkd, ch <-chan error) error {
					time.Sleep(time.Millisecond * 100)
					cancel()
					if k := j.keys.Load(); k == nil {
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
					athenzURL:     strings.Replace(srv.URL, "https://", "", 1),
					refreshPeriod: time.Millisecond * 10,
					retryDelay:    time.Millisecond,
					client:        srv.Client(),
				},
				args: args{
					ctx: ctx,
				},
				checkFunc: func(j *jwkd, ch <-chan error) error {
					time.Sleep(time.Millisecond * 100)
					k1 := j.keys.Load()
					if k1 == nil {
						return errors.New("cannot update keys")
					}

					time.Sleep(time.Millisecond * 30)
					cancel()

					k2 := j.keys.Load()
					if k2 == nil {
						return errors.New("cannot update keys")
					}

					if k1.(*jwk.Set).Keys[0].KeyID() == k2.(*jwk.Set).Keys[0].KeyID() {
						return errors.Errorf("key do not update after it starts, k1.KeyID: %v equals k2.KeyID: %v", k1.(*jwk.Set).Keys[0].KeyID(), k2.(*jwk.Set).Keys[0].KeyID())
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
					athenzURL:     strings.Replace(srv.URL, "https://", "", 1),
					refreshPeriod: time.Millisecond * 10,
					retryDelay:    time.Millisecond,
					client:        srv.Client(),
				},
				args: args{
					ctx: ctx,
				},
				checkFunc: func(j *jwkd, ch <-chan error) error {
					time.Sleep(time.Millisecond * 100)
					cancel()
					if k := j.keys.Load(); k == nil {
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
				athenzURL:     tt.fields.athenzURL,
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
		athenzURL     string
		refreshPeriod time.Duration
		retryDelay    time.Duration
		client        *http.Client
		keys          atomic.Value
	}
	type args struct {
		ctx context.Context
	}
	type test struct {
		name      string
		fields    fields
		args      args
		checkFunc func(*jwkd) error
		wantErr   bool
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
				name: "Update success",
				fields: fields{
					athenzURL: strings.Replace(srv.URL, "https://", "", 1),
					client:    srv.Client(),
				},
				args: args{
					ctx: context.Background(),
				},
				checkFunc: func(j *jwkd) error {
					val := j.keys.Load()
					if val == nil {
						return errors.New("keys is empty")
					}

					got := val.(*jwk.Set).Keys[0].KeyType()
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
				name: "Update fail",
				fields: fields{
					athenzURL: strings.Replace(srv.URL, "https://", "", 1),
					client:    srv.Client(),
				},
				args: args{
					ctx: context.Background(),
				},
				checkFunc: func(j *jwkd) error {
					if j.keys.Load() != nil {
						return errors.Errorf("keys expected nil")
					}
					return nil
				},
				wantErr: true,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := &jwkd{
				athenzURL:     tt.fields.athenzURL,
				refreshPeriod: tt.fields.refreshPeriod,
				retryDelay:    tt.fields.retryDelay,
				client:        tt.fields.client,
				keys:          tt.fields.keys,
			}
			if err := j.Update(tt.args.ctx); (err != nil) != tt.wantErr {
				t.Errorf("jwkd.Update() error = %v, wantErr %v", err, tt.wantErr)
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
		athenzURL     string
		refreshPeriod time.Duration
		retryDelay    time.Duration
		client        *http.Client
		keys          atomic.Value
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
				athenzURL:     tt.fields.athenzURL,
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
		athenzURL     string
		refreshPeriod time.Duration
		retryDelay    time.Duration
		client        *http.Client
		keys          atomic.Value
	}
	type args struct {
		keyID string
	}
	type test struct {
		name   string
		fields fields
		args   args
		want   interface{}
	}
	genKey := func() *rsa.PrivateKey {
		k, _ := rsa.GenerateKey(rand.Reader, 2048)
		k.Precomputed.CRTValues = nil
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
			k := newKey(rsaKey, "dummyID")
			set := &jwk.Set{
				Keys: []jwk.Key{
					k,
				},
			}
			key := atomic.Value{}
			key.Store(set)

			return test{
				name: "get key success",
				fields: fields{
					keys: key,
				},
				args: args{
					keyID: "dummyID",
				},
				want: rsaKey,
			}
		}(),
		func() test {
			rsaKey := genKey()
			k := newKey(rsaKey, "dummyID")
			set := &jwk.Set{
				Keys: []jwk.Key{
					k,
				},
			}

			key := atomic.Value{}
			key.Store(set)

			return test{
				name: "get key not found",
				fields: fields{
					keys: key,
				},
				args: args{
					keyID: "not exists",
				},
				want: nil,
			}
		}(),
		func() test {
			rsaKey := genKey()
			k := newKey(rsaKey, "")
			set := &jwk.Set{
				Keys: []jwk.Key{
					k,
				},
			}

			key := atomic.Value{}
			key.Store(set)

			return test{
				name: "get key id empty return nil",
				fields: fields{
					keys: key,
				},
				args: args{
					keyID: "",
				},
				want: nil,
			}
		}(),
		func() test {
			rsaKey1 := genKey()
			k1 := newKey(rsaKey1, "dummyID1")

			rsaKey2 := genKey()
			k2 := newKey(rsaKey2, "dummyID2")

			rsaKey3 := genKey()
			k3 := newKey(rsaKey3, "dummyID3")

			set := &jwk.Set{
				Keys: []jwk.Key{
					k1, k2, k3,
				},
			}
			key := atomic.Value{}
			key.Store(set)

			return test{
				name: "get key success from multiple key",
				fields: fields{
					keys: key,
				},
				args: args{
					keyID: "dummyID2",
				},
				want: rsaKey2,
			}
		}(),
		func() test {
			ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Errorf("ecdsa.GenerateKey: %s", err.Error())
			}
			k := newKey(ecKey, "ecKeyID")
			set := &jwk.Set{
				Keys: []jwk.Key{
					k,
				},
			}
			key := atomic.Value{}
			key.Store(set)

			return test{
				name: "get EC private key success",
				fields: fields{
					keys: key,
				},
				args: args{
					keyID: "ecKeyID",
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
			k := newKey(ecPubKey, "ecPubKeyID")
			set := &jwk.Set{
				Keys: []jwk.Key{
					k,
				},
			}
			key := atomic.Value{}
			key.Store(set)

			return test{
				name: "get EC public key success",
				fields: fields{
					keys: key,
				},
				args: args{
					keyID: "ecPubKeyID",
				},
				want: ecPubKey,
			}
		}(),
		func() test {
			rsaPubKey := genKey().Public()
			k := newKey(rsaPubKey, "rsaPubKeyID")
			set := &jwk.Set{
				Keys: []jwk.Key{
					k,
				},
			}
			key := atomic.Value{}
			key.Store(set)

			return test{
				name: "get RSA public key success",
				fields: fields{
					keys: key,
				},
				args: args{
					keyID: "rsaPubKeyID",
				},
				want: rsaPubKey,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := &jwkd{
				athenzURL:     tt.fields.athenzURL,
				refreshPeriod: tt.fields.refreshPeriod,
				retryDelay:    tt.fields.retryDelay,
				client:        tt.fields.client,
				keys:          tt.fields.keys,
			}
			if got := j.getKey(tt.args.keyID); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("jwkd.getKey() = %#v, want %#v", got, tt.want)
			}
		})
	}
}
