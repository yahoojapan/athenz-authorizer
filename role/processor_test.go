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

package role

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"reflect"
	"testing"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/kpango/fastime"
	authcore "github.com/yahoo/athenz/libs/go/zmssvctoken"
	"github.com/yahoojapan/athenz-authorizer/v2/jwk"
	"github.com/yahoojapan/athenz-authorizer/v2/pubkey"
)

// test data is generated by `role/asserts/private.pem`

func TestNew(t *testing.T) {
	type args struct {
		opts []Option
	}
	type test struct {
		name    string
		args    args
		want    Processor
		wantErr bool
	}
	tests := []test{
		{
			name: "new success",
			args: args{
				opts: nil,
			},
			want: &rtp{
				nil,
				nil,
				false,
				0,
				0,
			},
			wantErr: false,
		},
		{
			name: "new success, use option",
			args: args{
				opts: []Option{
					WithEnableMTLSCertificateBoundAccessToken(true),
				},
			},
			want: &rtp{
				nil,
				nil,
				true,
				0,
				0,
			},
			wantErr: false,
		},
		{
			name: "new fail, option is error",
			args: args{
				opts: []Option{
					WithClientCertificateGoBackSeconds("invalid-duration"),
				},
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.args.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v", err)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_rtp_ParseAndValidateRoleToken(t *testing.T) {
	type fields struct {
		pkp pubkey.Provider
	}
	type args struct {
		tok string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *Token
		wantErr bool
	}{
		{
			name: "parse validate success",
			fields: fields{
				pkp: func(pubkey.AthenzEnv, string) authcore.Verifier {
					return VerifierMock{
						VerifyFunc: func(string, string) error {
							return nil
						},
					}
				},
			},
			args: args{
				tok: "v=Z1;d=dummy.sidecartest;r=users;p=takumats.tenant.test;h=dummyhost;a=e55ee6ddc3e3c27c;t=1550463321;e=9999999999;k=0;i=172.16.168.25;s=dummysignature",
			},
			want: &Token{
				UnsignedToken: "v=Z1;d=dummy.sidecartest;r=users;p=takumats.tenant.test;h=dummyhost;a=e55ee6ddc3e3c27c;t=1550463321;e=9999999999;k=0;i=172.16.168.25",
				Domain:        "dummy.sidecartest",
				ExpiryTime:    time.Unix(9999999999, 0),
				KeyID:         "0",
				Roles:         []string{"users"},
				Signature:     "dummysignature",
			},
		},
		{
			name: "parse error",
			args: args{
				tok: "v=Z1;d=dummy.sidecartest;r=users;p=takumats.tenant.test;h=dummyhost;a=e55ee6ddc3e3c27c;t=1550463321;e=9999999999;k=0;i=172.16.168.25",
			},
			wantErr: true,
		},
		{
			name: "validate error",
			fields: fields{
				pkp: func(pubkey.AthenzEnv, string) authcore.Verifier {
					return VerifierMock{
						VerifyFunc: func(string, string) error {
							return fmt.Errorf("")
						},
					}
				},
			},
			args: args{
				tok: "v=Z1;d=dummy.sidecartest;r=users;p=takumats.tenant.test;h=dummyhost;a=e55ee6ddc3e3c27c;t=1550463321;e=9999999999;k=0;i=172.16.168.25;s=dummysignature",
			},
			wantErr: true,
		},
		{
			name: "parse invalid token with extra args after signature",
			fields: fields{
				pkp: func(pubkey.AthenzEnv, string) authcore.Verifier {
					return VerifierMock{
						VerifyFunc: func(string, string) error {
							return nil
						},
					}
				},
			},
			args: args{
				tok: "v=Z1;d=dummy.sidecartest;r=users;p=takumats.tenant.test;h=dummyhost;a=e55ee6ddc3e3c27c;t=1550463321;e=9999999999;k=0;i=172.16.168.25;s=dummysignature;d=dummy1;r=users2",
			},
			want: &Token{
				UnsignedToken: "v=Z1;d=dummy.sidecartest;r=users;p=takumats.tenant.test;h=dummyhost;a=e55ee6ddc3e3c27c;t=1550463321;e=9999999999;k=0;i=172.16.168.25",
				Domain:        "dummy.sidecartest",
				ExpiryTime:    time.Unix(9999999999, 0),
				KeyID:         "0",
				Roles:         []string{"users"},
				Signature:     "dummysignature;d=dummy1;r=users2",
			},
		},
		{
			name: "parse invalid token with 2 signature",
			fields: fields{
				pkp: func(pubkey.AthenzEnv, string) authcore.Verifier {
					return VerifierMock{
						VerifyFunc: func(string, string) error {
							return nil
						},
					}
				},
			},
			args: args{
				tok: "v=Z1;d=dummy.sidecartest;r=users;p=takumats.tenant.test;h=dummyhost;a=e55ee6ddc3e3c27c;t=1550463321;e=9999999999;k=0;i=172.16.168.25;s=dummysignature;s=dummysignature2",
			},
			want: &Token{
				UnsignedToken: "v=Z1;d=dummy.sidecartest;r=users;p=takumats.tenant.test;h=dummyhost;a=e55ee6ddc3e3c27c;t=1550463321;e=9999999999;k=0;i=172.16.168.25",
				Domain:        "dummy.sidecartest",
				ExpiryTime:    time.Unix(9999999999, 0),
				KeyID:         "0",
				Roles:         []string{"users"},
				Signature:     "dummysignature;s=dummysignature2",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &rtp{
				pkp: tt.fields.pkp,
			}
			got, err := r.ParseAndValidateRoleToken(tt.args.tok)
			if (err != nil) != tt.wantErr {
				t.Errorf("rtp.ParseAndValidateRoleToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("rtp.ParseAndValidateRoleToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_rtp_parseToken(t *testing.T) {
	type fields struct {
		pkp pubkey.Provider
	}
	type args struct {
		tok string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *Token
		wantErr bool
	}{
		{
			name: "parse success",
			args: args{
				tok: "v=Z1;d=dummy.sidecartest;r=users;p=takumats.tenant.test;h=dummyhost;a=e55ee6ddc3e3c27c;t=1550463321;e=1550643321;k=0;i=172.16.168.25;s=dummysignature",
			},
			want: &Token{
				UnsignedToken: "v=Z1;d=dummy.sidecartest;r=users;p=takumats.tenant.test;h=dummyhost;a=e55ee6ddc3e3c27c;t=1550463321;e=1550643321;k=0;i=172.16.168.25",
				Domain:        "dummy.sidecartest",
				ExpiryTime:    time.Date(2019, 2, 20, 6, 15, 21, 0, time.UTC).Local(),
				KeyID:         "0",
				Roles:         []string{"users"},
				Signature:     "dummysignature",
			},
		},
		{
			name: "signature not found",
			args: args{
				tok: "v=Z1;d=dummy.sidecartest;r=users;p=takumats.tenant.test;h=dummyhost;a=e55ee6ddc3e3c27c;t=1550463321;e=1550643321;k=0;i=172.16.168.25",
			},
			wantErr: true,
		},
		{
			name: "invalid key value format",
			args: args{
				tok: "v=Z1;d=dummy.sidecartest=;r=users;eabcd;s=dummy",
			},
			wantErr: true,
		},
		{
			name: "set value error",
			args: args{
				tok: "v=Z1;d=dummy.sidecartest=;r=users;e=abcd;s=dummy",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &rtp{
				pkp: tt.fields.pkp,
			}
			got, err := r.parseToken(tt.args.tok)
			if (err != nil) != tt.wantErr {
				t.Errorf("rtp.parseToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("rtp.parseToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_rtp_validate(t *testing.T) {
	type fields struct {
		pkp pubkey.Provider
	}
	type args struct {
		rt *Token
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "validate success",
			fields: fields{
				pkp: func(pubkey.AthenzEnv, string) authcore.Verifier {
					return VerifierMock{
						VerifyFunc: func(string, string) error {
							return nil
						},
					}
				},
			},
			args: args{
				&Token{
					ExpiryTime: fastime.Now().Add(time.Hour),
				},
			},
		},
		{
			name: "token expired",
			fields: fields{
				pkp: func(pubkey.AthenzEnv, string) authcore.Verifier {
					return VerifierMock{
						VerifyFunc: func(string, string) error {
							return nil
						},
					}
				},
			},
			args: args{
				&Token{
					ExpiryTime: fastime.Now().Add(-1 * time.Hour),
				},
			},
			wantErr: true,
		},
		{
			name: "validate error",
			fields: fields{
				pkp: func(pubkey.AthenzEnv, string) authcore.Verifier {
					return VerifierMock{
						VerifyFunc: func(string, string) error {
							return fmt.Errorf("")
						},
					}
				},
			},
			args: args{
				&Token{
					ExpiryTime: fastime.Now().Add(time.Hour),
				},
			},
			wantErr: true,
		},
		{
			name: "verifier not found",
			fields: fields{
				pkp: func(pubkey.AthenzEnv, string) authcore.Verifier {
					return nil
				},
			},
			args: args{
				&Token{
					ExpiryTime: fastime.Now().Add(time.Hour),
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &rtp{
				pkp: tt.fields.pkp,
			}
			if err := r.validate(tt.args.rt); (err != nil) != tt.wantErr {
				t.Errorf("rtp.validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_rtp_ParseAndValidateRoleJWT(t *testing.T) {
	type fields struct {
		pkp  pubkey.Provider
		jwkp jwk.Provider
	}
	type args struct {
		cred string
	}
	type test struct {
		name    string
		fields  fields
		args    args
		want    *RoleJWTClaim
		wantErr bool
	}

	LoadRSAPublicKeyFromDisk := func(location string) *rsa.PublicKey {
		keyData, e := ioutil.ReadFile(location)
		if e != nil {
			panic(e.Error())
		}
		key, e := jwt.ParseRSAPublicKeyFromPEM(keyData)
		if e != nil {
			panic(e.Error())
		}
		return key
	}

	tests := []test{
		func() test {
			return test{
				name: "verify jwt success",
				fields: fields{
					jwkp: jwk.Provider(func(kid string) interface{} {
						return LoadRSAPublicKeyFromDisk("./asserts/public.pem")
					}),
				},
				args: args{
					cred: `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6dHJ1ZSwiZXhwIjo5OTk5OTk5OTk5fQ.MBv8JoDPjlwhwCzPdkVH0C7HGjtLsVdVsbduNSbnIVtLEcD1yfsVqUKpUupYx2h6o_gKgjTbNG2C6zidV6YsxXu5s-D-YSN15MO_Mjm1WJducK0OJURC8o7u83LcgoEXZQTjA3gQVBGSbyNELCBQKN451OHMOPcIYDLdgXS4iqiZPPBxd1VuNGoMtUshZQR5mGp5F3Yk1YQg9QPicN4-gDh-PF5l87ouTj6O1WyxGuY2qHmGzun3xe_Ma1kzslbL95MtzOLR6seCaSCfanUxC2FjD2hPj4I7HZuYIIFsQRAb_pguhh4dkEkb3op5XcpgoHQr26SlkKAUEFLmUa6qvg`,
				},
				want: func() *RoleJWTClaim {
					c := &RoleJWTClaim{}
					c.ExpiresAt = 9999999999
					return c
				}(),
				wantErr: false,
			}
		}(),
		func() test {
			return test{
				name: "verify jwt fail, no expiration defined",
				fields: fields{
					jwkp: jwk.Provider(func(kid string) interface{} {
						return LoadRSAPublicKeyFromDisk("./asserts/public.pem")
					}),
				},
				args: args{
					cred: `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6dHJ1ZX0.UtLx_xg2OWF7_sk9P7jcBsS9WqE4st_gvSskRoG92ktDXjSsBa-p2LmArFnFHp-cb3qnXUwc3_Ksg9w10r0iVpxg8lZfGUCmIfauaaoCuxRdogWIAaY4mIXyglQcSgIruo17wMJ-kHyJxr50lWMiyxFYf6ANUE8W2FaiDgwQuGraF4UQKDwmytGai1mHnc8_u5CanEmETWdax-Pe37BikPorljCIoYIyMTpIfdjM3A8s5Ipo8SHagnUPU0a-jS1sU2UjLo4vnDnPwur_6d5im9XuZD6DGHgaQRo4Zh-ZdvEJR8QTtdb2op14jzTaQGLYJNbPiH8yklBhtKMCAPHFuw`,
				},
				wantErr: true,
			}
		}(),
		func() test {
			return test{
				name: "verify jwt fail, expired jwt",
				fields: fields{
					jwkp: jwk.Provider(func(kid string) interface{} {
						return LoadRSAPublicKeyFromDisk("./asserts/public.pem")
					}),
				},
				args: args{
					cred: `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6dHJ1ZSwiZXhwIjoxfQ.h5jrpuSZDjpqo8Ri-yUzq22qis_CIMuTQE6WR5myHW8Z8VhEOLInZU59kmu5Ardud3gjjtMI6kIJrUcVeYBcmE_MG4iMiah767hB-09Bm_lmh6mdEK3wP_m8_JX4OWKHqHyZSZgjJKGNCT-yHZEXuOLpydCLpIaL7znAA3-eDAnyUjZcVipA0J-BwS1I27zHOW6NumQEuXQMau2f1pH4Z77e3etNGA3yG7yG30YaqaSEWfah9BMZwgLx2fnuHAbcyNEpSl5nHZYdTyINtMsurUkDuou8c1G0WIvu4Rn2Wksey0GWdVNsclqeNaFsgsHyVwKsOVFvslQ3qTcwSjw73Q`,
				},
				wantErr: true,
			}
		}(),
		func() test {
			return test{
				name: "verify jwt fail, invalid signature",
				fields: fields{
					jwkp: jwk.Provider(func(kid string) interface{} {
						return LoadRSAPublicKeyFromDisk("./asserts/public.pem")
					}),
				},
				args: args{
					cred: `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6dHJ1ZSwiZXhwIjoxfQ.h5jrpuSZDjpqo8Ri-yUzq22qis_CIMuTQE6WR5myHW8Z8VhEOLInZU59kmu5Ardud3gjjtMI6kIJrUcVeYBcmE_MG4iMiah767hB-09Bm_lmh6mdEK3wP_m8_JX4OWKHqHyZSZgjJKGNCT-yHZEXuOLpydCLpIaL7znAA3-eDAnyUjZcVipA0J-BwS1I27zHOW6NumQEuXQMau2f1pH4Z77e3etNGA3yG7yG30YaqaSEWfah9BMZwgLx2fnuHAbcyNEpSl5nHZYdTyINtMsurUkDuou8c1G0WIvu4Rn2Wksey0GWdVNsclqeNaFsgsHyVwKsOVFvslQ3qTcwSjw73Qe`,
				},
				wantErr: true,
			}
		}(),
		func() test {
			return test{
				name: "verify jwt fail, invalid jwt format",
				fields: fields{
					jwkp: jwk.Provider(func(kid string) interface{} {
						return LoadRSAPublicKeyFromDisk("./asserts/public.pem")
					}),
				},
				args: args{
					cred: `dummy`,
				},
				wantErr: true,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &rtp{
				pkp:  tt.fields.pkp,
				jwkp: tt.fields.jwkp,
			}
			got, err := r.ParseAndValidateRoleJWT(tt.args.cred)
			if (err != nil) != tt.wantErr {
				t.Errorf("rtp.ParseAndValidateRoleJWT() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("rtp.ParseAndValidateRoleJWT() = %+v, want %v", got, tt.want)
			}
		})
	}
}

func Test_rtp_keyFunc(t *testing.T) {
	type fields struct {
		pkp  pubkey.Provider
		jwkp jwk.Provider
	}
	type args struct {
		token *jwt.Token
	}
	type test struct {
		name    string
		fields  fields
		args    args
		want    interface{}
		wantErr bool
	}
	tests := []test{
		{
			name: "key return success",
			fields: fields{
				jwkp: jwk.Provider(func(kid string) interface{} {
					if kid == "1" {
						return "key"
					}
					return nil
				}),
			},
			args: args{
				token: &jwt.Token{
					Header: map[string]interface{}{
						"kid": "1",
					},
				},
			},
			want: "key",
		},
		{
			name: "key header not found",
			fields: fields{
				jwkp: jwk.Provider(func(kid string) interface{} {
					if kid == "1" {
						return "key"
					}
					return nil
				}),
			},
			args: args{
				token: &jwt.Token{
					Header: map[string]interface{}{},
				},
			},
			wantErr: true,
		},
		{
			name: "key not found",
			fields: fields{
				jwkp: jwk.Provider(func(kid string) interface{} {
					if kid == "1" {
						return nil
					}
					return "key"
				}),
			},
			args: args{
				token: &jwt.Token{
					Header: map[string]interface{}{
						"kid": "1",
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &rtp{
				pkp:  tt.fields.pkp,
				jwkp: tt.fields.jwkp,
			}
			got, err := r.keyFunc(tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("rtp.keyFunc() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("rtp.keyFunc() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_rtp_ParseAndValidateZTSAccessToken(t *testing.T) {
	type fields struct {
		pkp                                   pubkey.Provider
		jwkp                                  jwk.Provider
		enableMTLSCertificateBoundAccessToken bool
	}
	type args struct {
		cred string
		cert *x509.Certificate
	}
	type test struct {
		name    string
		fields  fields
		args    args
		want    *ZTSAccessTokenClaim
		wantErr bool
	}

	LoadRSAPublicKeyFromDisk := func(location string) *rsa.PublicKey {
		keyData, e := ioutil.ReadFile(location)
		if e != nil {
			panic(e.Error())
		}
		key, e := jwt.ParseRSAPublicKeyFromPEM(keyData)
		if e != nil {
			panic(e.Error())
		}
		return key
	}

	LoadX509CertFromDisk := func(location string) *x509.Certificate {
		certData, e := ioutil.ReadFile(location)
		if e != nil {
			panic(e.Error())
		}
		block, _ := pem.Decode(certData)
		if block == nil {
			panic("pem decode error")
		}
		cert, e := x509.ParseCertificate(block.Bytes)
		if e != nil {
			panic(e.Error())
		}
		return cert
	}

	tests := []test{
		func() test {
			return test{
				name: "verify access token success",
				fields: fields{
					jwkp: jwk.Provider(func(kid string) interface{} {
						return LoadRSAPublicKeyFromDisk("./asserts/public.pem")
					}),
				},
				args: args{
					cred: `eyJraWQiOiIwIiwidHlwIjoiYXQrand0IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJkb21haW4udGVuYW50LnNlcnZpY2UiLCJpYXQiOjE1ODQ1MTM0NDEsImV4cCI6OTk5OTk5OTk5OSwiaXNzIjoiaHR0cHM6Ly96dHMuYXRoZW56LmlvIiwiYXVkIjoiZG9tYWluLnByb3ZpZGVyIiwiYXV0aF90aW1lIjoxNTg0NTEzNDQxLCJ2ZXIiOjEsInNjcCI6WyJhZG1pbiIsInVzZXIiXSwidWlkIjoiZG9tYWluLnRlbmFudC5zZXJ2aWNlIiwiY2xpZW50X2lkIjoiZG9tYWluLnRlbmFudC5zZXJ2aWNlIn0.WYQqy87f6sBSJrtcw5ZcfjZx6kq4dT4elCY0_cfo7c6wMESkdGKXDDdZh8Dxq3qoZCl29oEYTFrDYDzWg_HPUZ34PTEt-W3g_5utZ3J3P7x6gyGKmk7aRFHsX7SVwlxcEBKENQMwctd6j54z4GYD8eTRdqTDSYYTWID7XSGDk77t5qX2tJOnbLYv4GuspRrkZBted-K_D6bhVMVptcKpMBfwtQErx345W0X0c5Am06pdK_7a3DJnQXJ1sOWKMjiQVgFIfjEkzzmkkWdaSPhqX-UUWHzPDTvfcgV-9Ojw_nxJq_WU04MaDSEyJDs6K-c4HniMEaQfHsYIgYLt4Lq3Cg`,
				},
				want: func() *ZTSAccessTokenClaim {
					c := ZTSAccessTokenClaim{
						BaseClaim: BaseClaim{
							StandardClaims: jwt.StandardClaims{
								Subject:   "domain.tenant.service",
								IssuedAt:  1584513441,
								ExpiresAt: 9999999999,
								Issuer:    "https://zts.athenz.io",
								Audience:  "domain.provider",
							},
						},
						AuthTime: 1584513441,
						Version:  1,
						ClientID: "domain.tenant.service",
						UserID:   "domain.tenant.service",
						Scope:    []string{"admin", "user"},
					}
					return &c
				}(),
				wantErr: false,
			}
		}(),
		func() test {
			return test{
				name: "verify certificate bound access token success",
				fields: fields{
					jwkp: jwk.Provider(func(kid string) interface{} {
						return LoadRSAPublicKeyFromDisk("./asserts/public.pem")
					}),
					enableMTLSCertificateBoundAccessToken: true,
				},
				args: args{
					cred: `eyJraWQiOiIwIiwidHlwIjoiYXQrand0IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJkb21haW4udGVuYW50LnNlcnZpY2UiLCJpYXQiOjE1ODUxMjIzODEsImV4cCI6OTk5OTk5OTk5OSwiaXNzIjoiaHR0cHM6Ly96dHMuYXRoZW56LmlvIiwiYXVkIjoiZG9tYWluLnByb3ZpZGVyIiwiYXV0aF90aW1lIjoxNTg1MTIyMzgxLCJ2ZXIiOjEsInNjcCI6WyJhZG1pbiIsInVzZXIiXSwidWlkIjoiZG9tYWluLnRlbmFudC5zZXJ2aWNlIiwiY2xpZW50X2lkIjoiZG9tYWluLnRlbmFudC5zZXJ2aWNlIiwiY25mIjp7Ing1dCNTMjU2IjoiMmp0ODJmMnVNOGpFMkxNY2I0ZXJoaFRjLXV5MXlCMWlFeXA1TW5JNXVGNCJ9fQ.OyotreYeMFDTpDaIoPVnEBY1RnVuzRortfRKnkOfZUEv1wSSmgSPxBE9IfgxD57kCQUJtO4GUBUWX_DrIb8BMMVUaDlws6UTncaCUdTt_lJXuIZilh7vIA5oiRTtpADJrZUS3kH2ln6qTXa1QTeevg5qdfORya7ILiHdJUmQXbb9vndYcS4-4E3Xr7rqj7cD67rvySM8YIOsaMn2UX237VUo2rcs40XuHH6WCFfix4xxmgTxS7zr_uowqxpXrgpc0g_eT4On9gnuTDcAzwVy7qbgWMcEO-UrhV_FiPzIRj5RZFZBeHjNeU2QAAT-LAw7S6YJtlPpijfTM9qx6xC0GA`,
					cert: func() *x509.Certificate {
						return LoadX509CertFromDisk("./asserts/dummyClient.crt")
					}(),
				},
				want: func() *ZTSAccessTokenClaim {
					c := ZTSAccessTokenClaim{
						BaseClaim: BaseClaim{
							StandardClaims: jwt.StandardClaims{
								Subject:   "domain.tenant.service",
								IssuedAt:  1585122381,
								ExpiresAt: 9999999999,
								Issuer:    "https://zts.athenz.io",
								Audience:  "domain.provider",
							},
						},
						AuthTime: 1585122381,
						Version:  1,
						ClientID: "domain.tenant.service",
						UserID:   "domain.tenant.service",
						Scope:    []string{"admin", "user"},
						Confirm:  map[string]string{"x5t#S256": "2jt82f2uM8jE2LMcb4erhhTc-uy1yB1iEyp5MnI5uF4"},
					}
					return &c
				}(),
				wantErr: false,
			}
		}(),
		func() test {
			return test{
				name: "verify access token fail, no expiration defined",
				fields: fields{
					jwkp: jwk.Provider(func(kid string) interface{} {
						return LoadRSAPublicKeyFromDisk("./asserts/public.pem")
					}),
				},
				args: args{
					cred: `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6dHJ1ZX0.UtLx_xg2OWF7_sk9P7jcBsS9WqE4st_gvSskRoG92ktDXjSsBa-p2LmArFnFHp-cb3qnXUwc3_Ksg9w10r0iVpxg8lZfGUCmIfauaaoCuxRdogWIAaY4mIXyglQcSgIruo17wMJ-kHyJxr50lWMiyxFYf6ANUE8W2FaiDgwQuGraF4UQKDwmytGai1mHnc8_u5CanEmETWdax-Pe37BikPorljCIoYIyMTpIfdjM3A8s5Ipo8SHagnUPU0a-jS1sU2UjLo4vnDnPwur_6d5im9XuZD6DGHgaQRo4Zh-ZdvEJR8QTtdb2op14jzTaQGLYJNbPiH8yklBhtKMCAPHFuw`,
				},
				wantErr: true,
			}
		}(),
		func() test {
			return test{
				name: "verify access token fail, expired jwt",
				fields: fields{
					jwkp: jwk.Provider(func(kid string) interface{} {
						return LoadRSAPublicKeyFromDisk("./asserts/public.pem")
					}),
				},
				args: args{
					cred: `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6dHJ1ZSwiZXhwIjoxfQ.h5jrpuSZDjpqo8Ri-yUzq22qis_CIMuTQE6WR5myHW8Z8VhEOLInZU59kmu5Ardud3gjjtMI6kIJrUcVeYBcmE_MG4iMiah767hB-09Bm_lmh6mdEK3wP_m8_JX4OWKHqHyZSZgjJKGNCT-yHZEXuOLpydCLpIaL7znAA3-eDAnyUjZcVipA0J-BwS1I27zHOW6NumQEuXQMau2f1pH4Z77e3etNGA3yG7yG30YaqaSEWfah9BMZwgLx2fnuHAbcyNEpSl5nHZYdTyINtMsurUkDuou8c1G0WIvu4Rn2Wksey0GWdVNsclqeNaFsgsHyVwKsOVFvslQ3qTcwSjw73Q`,
				},
				wantErr: true,
			}
		}(),
		func() test {
			return test{
				name: "verify access token fail, invalid signature",
				fields: fields{
					jwkp: jwk.Provider(func(kid string) interface{} {
						return LoadRSAPublicKeyFromDisk("./asserts/public.pem")
					}),
				},
				args: args{
					cred: `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6dHJ1ZSwiZXhwIjoxfQ.h5jrpuSZDjpqo8Ri-yUzq22qis_CIMuTQE6WR5myHW8Z8VhEOLInZU59kmu5Ardud3gjjtMI6kIJrUcVeYBcmE_MG4iMiah767hB-09Bm_lmh6mdEK3wP_m8_JX4OWKHqHyZSZgjJKGNCT-yHZEXuOLpydCLpIaL7znAA3-eDAnyUjZcVipA0J-BwS1I27zHOW6NumQEuXQMau2f1pH4Z77e3etNGA3yG7yG30YaqaSEWfah9BMZwgLx2fnuHAbcyNEpSl5nHZYdTyINtMsurUkDuou8c1G0WIvu4Rn2Wksey0GWdVNsclqeNaFsgsHyVwKsOVFvslQ3qTcwSjw73Qe`,
				},
				wantErr: true,
			}
		}(),
		func() test {
			return test{
				name: "verify access token fail, invalid jwt format",
				fields: fields{
					jwkp: jwk.Provider(func(kid string) interface{} {
						return LoadRSAPublicKeyFromDisk("./asserts/public.pem")
					}),
				},
				args: args{
					cred: `dummy`,
				},
				wantErr: true,
			}
		}(),
		func() test {
			return test{
				name: "verify certificate bound access token fail, no cert",
				fields: fields{
					jwkp: jwk.Provider(func(kid string) interface{} {
						return LoadRSAPublicKeyFromDisk("./asserts/public.pem")
					}),
					enableMTLSCertificateBoundAccessToken: true,
				},
				args: args{
					cred: `eyJraWQiOiIwIiwidHlwIjoiYXQrand0IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJkb21haW4udGVuYW50LnNlcnZpY2UiLCJpYXQiOjE1ODUxMjIzODEsImV4cCI6OTk5OTk5OTk5OSwiaXNzIjoiaHR0cHM6Ly96dHMuYXRoZW56LmlvIiwiYXVkIjoiZG9tYWluLnByb3ZpZGVyIiwiYXV0aF90aW1lIjoxNTg1MTIyMzgxLCJ2ZXIiOjEsInNjcCI6WyJhZG1pbiIsInVzZXIiXSwidWlkIjoiZG9tYWluLnRlbmFudC5zZXJ2aWNlIiwiY2xpZW50X2lkIjoiZG9tYWluLnRlbmFudC5zZXJ2aWNlIiwiY25mIjp7Ing1dCNTMjU2IjoiMmp0ODJmMnVNOGpFMkxNY2I0ZXJoaFRjLXV5MXlCMWlFeXA1TW5JNXVGNCJ9fQ.OyotreYeMFDTpDaIoPVnEBY1RnVuzRortfRKnkOfZUEv1wSSmgSPxBE9IfgxD57kCQUJtO4GUBUWX_DrIb8BMMVUaDlws6UTncaCUdTt_lJXuIZilh7vIA5oiRTtpADJrZUS3kH2ln6qTXa1QTeevg5qdfORya7ILiHdJUmQXbb9vndYcS4-4E3Xr7rqj7cD67rvySM8YIOsaMn2UX237VUo2rcs40XuHH6WCFfix4xxmgTxS7zr_uowqxpXrgpc0g_eT4On9gnuTDcAzwVy7qbgWMcEO-UrhV_FiPzIRj5RZFZBeHjNeU2QAAT-LAw7S6YJtlPpijfTM9qx6xC0GA`,
					cert: nil,
				},
				wantErr: true,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &rtp{
				pkp:                                   tt.fields.pkp,
				jwkp:                                  tt.fields.jwkp,
				enableMTLSCertificateBoundAccessToken: tt.fields.enableMTLSCertificateBoundAccessToken,
			}
			got, err := r.ParseAndValidateZTSAccessToken(tt.args.cred, tt.args.cert)
			if (err != nil) != tt.wantErr {
				t.Errorf("rtp.ParseAndValidateZTSAccessToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("rtp.ParseAndValidateZTSAccessToken() = %+v, want %v", got, tt.want)
			}
		})
	}
}

func Test_rtp_validateCertificateBoundAccessToken(t *testing.T) {
	type fields struct {
		pkp                                   pubkey.Provider
		jwkp                                  jwk.Provider
		enableMTLSCertificateBoundAccessToken bool
		clientCertificateGoBackSeconds        int64
		clientCertificateOffsetSeconds        int64
	}
	type args struct {
		cert   *x509.Certificate
		claims *ZTSAccessTokenClaim
	}
	LoadRSAPublicKeyFromDisk := func(location string) *rsa.PublicKey {
		keyData, e := ioutil.ReadFile(location)
		if e != nil {
			panic(e.Error())
		}
		key, e := jwt.ParseRSAPublicKeyFromPEM(keyData)
		if e != nil {
			panic(e.Error())
		}
		return key
	}

	LoadX509CertFromDisk := func(location string) *x509.Certificate {
		certData, e := ioutil.ReadFile(location)
		if e != nil {
			panic(e.Error())
		}
		block, _ := pem.Decode(certData)
		if block == nil {
			panic("pem decode error")
		}
		cert, e := x509.ParseCertificate(block.Bytes)
		if e != nil {
			panic(e.Error())
		}
		return cert
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "verify certificate bound accecss token success",
			fields: fields{
				jwkp: jwk.Provider(func(kid string) interface{} {
					return LoadRSAPublicKeyFromDisk("./asserts/public.pem")
				}),
				enableMTLSCertificateBoundAccessToken: true,
			},
			args: args{
				cert: func() *x509.Certificate {
					return LoadX509CertFromDisk("./asserts/dummyClient.crt")
				}(),
				claims: &ZTSAccessTokenClaim{
					BaseClaim: BaseClaim{
						StandardClaims: jwt.StandardClaims{
							Subject:   "domain.tenant.service",
							IssuedAt:  1585122381,
							ExpiresAt: 9999999999,
							Issuer:    "https://zts.athenz.io",
							Audience:  "domain.provider",
						},
					},
					AuthTime: 1585122381,
					Version:  1,
					ClientID: "domain.tenant.service",
					UserID:   "domain.tenant.service",
					Scope:    []string{"admin", "user"},
					Confirm:  map[string]string{"x5t#S256": "2jt82f2uM8jE2LMcb4erhhTc-uy1yB1iEyp5MnI5uF4"},
				},
			},
			wantErr: false,
		},
		{
			name: "verify certificate bound accecss token success, refreshed certificate",
			fields: fields{
				jwkp: jwk.Provider(func(kid string) interface{} {
					return LoadRSAPublicKeyFromDisk("./asserts/public.pem")
				}),
				enableMTLSCertificateBoundAccessToken: true,
				clientCertificateOffsetSeconds:        3600,
			},
			args: args{
				cert: &x509.Certificate{
					KeyUsage: x509.KeyUsageDigitalSignature,
					Subject: pkix.Name{
						CommonName: "domain.tenant.service",
					},
					NotBefore: time.Unix(1585122381+100, 0), // token's IssuedAt + 100
					NotAfter:  time.Unix(9999999999, 0),
				},
				claims: &ZTSAccessTokenClaim{
					BaseClaim: BaseClaim{
						StandardClaims: jwt.StandardClaims{
							Subject:   "domain.tenant.service",
							IssuedAt:  1585122381,
							ExpiresAt: 9999999999,
							Issuer:    "https://zts.athenz.io",
							Audience:  "domain.provider",
						},
					},
					AuthTime: 1585122381,
					Version:  1,
					ClientID: "domain.tenant.service",
					UserID:   "domain.tenant.service",
					Scope:    []string{"admin", "user"},
					Confirm:  map[string]string{"x5t#S256": "2jt82f2uM8jE2LMcb4erhhTc-uy1yB1iEyp5MnI5uF4"},
				},
			},
			wantErr: false,
		},
		{
			name: "verify certificate bound accecss token fail, cert is nil",
			fields: fields{
				jwkp: jwk.Provider(func(kid string) interface{} {
					return LoadRSAPublicKeyFromDisk("./asserts/public.pem")
				}),
				enableMTLSCertificateBoundAccessToken: true,
			},
			args: args{
				cert: nil,
				claims: &ZTSAccessTokenClaim{
					BaseClaim: BaseClaim{
						StandardClaims: jwt.StandardClaims{
							Subject:   "domain.tenant.service",
							IssuedAt:  1585122381,
							ExpiresAt: 9999999999,
							Issuer:    "https://zts.athenz.io",
							Audience:  "domain.provider",
						},
					},
					AuthTime: 1585122381,
					Version:  1,
					ClientID: "domain.tenant.service",
					UserID:   "domain.tenant.service",
					Scope:    []string{"admin", "user"},
					Confirm:  map[string]string{"x5t#S256": "2jt82f2uM8jE2LMcb4erhhTc-uy1yB1iEyp5MnI5uF4"},
				},
			},
			wantErr: true,
		},
		{
			name: "verify certificate bound accecss token fail, no confirmation claim",
			fields: fields{
				jwkp: jwk.Provider(func(kid string) interface{} {
					return LoadRSAPublicKeyFromDisk("./asserts/public.pem")
				}),
				enableMTLSCertificateBoundAccessToken: true,
			},
			args: args{
				cert: func() *x509.Certificate {
					return LoadX509CertFromDisk("./asserts/dummyClient.crt")
				}(),
				claims: &ZTSAccessTokenClaim{
					BaseClaim: BaseClaim{
						StandardClaims: jwt.StandardClaims{
							Subject:   "domain.tenant.service",
							IssuedAt:  1585122381,
							ExpiresAt: 9999999999,
							Issuer:    "https://zts.athenz.io",
							Audience:  "domain.provider",
						},
					},
					AuthTime: 1585122381,
					Version:  1,
					ClientID: "domain.tenant.service",
					UserID:   "domain.tenant.service",
					Scope:    []string{"admin", "user"},
				},
			},
			wantErr: true,
		},
		{
			name: "verify certificate bound accecss token fail, cnf check fail and no client_id",
			fields: fields{
				jwkp: jwk.Provider(func(kid string) interface{} {
					return LoadRSAPublicKeyFromDisk("./asserts/public.pem")
				}),
				enableMTLSCertificateBoundAccessToken: true,
			},
			args: args{
				cert: &x509.Certificate{
					KeyUsage: x509.KeyUsageDigitalSignature,
					Subject: pkix.Name{
						CommonName: "dummy",
					},
					NotBefore: time.Now(),
					NotAfter:  time.Unix(9999999999, 0),
				},
				claims: &ZTSAccessTokenClaim{
					BaseClaim: BaseClaim{
						StandardClaims: jwt.StandardClaims{
							Subject:   "domain.tenant.service",
							IssuedAt:  1585122381,
							ExpiresAt: 9999999999,
							Issuer:    "https://zts.athenz.io",
							Audience:  "domain.provider",
						},
					},
					AuthTime: 1585122381,
					Version:  1,
					UserID:   "domain.tenant.service",
					Scope:    []string{"admin", "user"},
					Confirm:  map[string]string{"x5t#S256": "2jt82f2uM8jE2LMcb4erhhTc-uy1yB1iEyp5MnI5uF4"},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &rtp{
				pkp:                                   tt.fields.pkp,
				jwkp:                                  tt.fields.jwkp,
				enableMTLSCertificateBoundAccessToken: tt.fields.enableMTLSCertificateBoundAccessToken,
				clientCertificateGoBackSeconds:        tt.fields.clientCertificateGoBackSeconds,
				clientCertificateOffsetSeconds:        tt.fields.clientCertificateOffsetSeconds,
			}
			if err := r.validateCertificateBoundAccessToken(tt.args.cert, tt.args.claims); (err != nil) != tt.wantErr {
				t.Errorf("rtp.validateCertificateBoundAccessToken() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_rtp_validateCertPrincipal(t *testing.T) {
	type fields struct {
		pkp                                   pubkey.Provider
		jwkp                                  jwk.Provider
		enableMTLSCertificateBoundAccessToken bool
		clientCertificateGoBackSeconds        int64
		clientCertificateOffsetSeconds        int64
	}
	type args struct {
		cert   *x509.Certificate
		claims *ZTSAccessTokenClaim
	}
	LoadRSAPublicKeyFromDisk := func(location string) *rsa.PublicKey {
		keyData, e := ioutil.ReadFile(location)
		if e != nil {
			panic(e.Error())
		}
		key, e := jwt.ParseRSAPublicKeyFromPEM(keyData)
		if e != nil {
			panic(e.Error())
		}
		return key
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "verify cert principal success",
			fields: fields{
				jwkp: jwk.Provider(func(kid string) interface{} {
					return LoadRSAPublicKeyFromDisk("./asserts/public.pem")
				}),
				enableMTLSCertificateBoundAccessToken: true,
				clientCertificateOffsetSeconds:        3600,
			},
			args: args{
				cert: &x509.Certificate{
					KeyUsage: x509.KeyUsageDigitalSignature,
					Subject: pkix.Name{
						CommonName: "domain.tenant.service",
					},
					NotBefore: time.Unix(1585122381+100, 0), // token's IssuedAt + 100
					NotAfter:  time.Unix(9999999999, 0),
				},
				claims: &ZTSAccessTokenClaim{
					BaseClaim: BaseClaim{
						StandardClaims: jwt.StandardClaims{
							Subject:   "domain.tenant.service",
							IssuedAt:  1585122381,
							ExpiresAt: 9999999999,
							Issuer:    "https://zts.athenz.io",
							Audience:  "domain.provider",
						},
					},
					ClientID: "domain.tenant.service",
					Confirm:  map[string]string{"x5t#S256": "dummy"},
				},
			},
		},
		{
			name: "verify cert principal success, token and certificate are issued at same time",
			fields: fields{
				jwkp: jwk.Provider(func(kid string) interface{} {
					return LoadRSAPublicKeyFromDisk("./asserts/public.pem")
				}),
				enableMTLSCertificateBoundAccessToken: true,
				clientCertificateOffsetSeconds:        3600,
			},
			args: args{
				cert: &x509.Certificate{
					KeyUsage: x509.KeyUsageDigitalSignature,
					Subject: pkix.Name{
						CommonName: "domain.tenant.service",
					},
					NotBefore: time.Unix(1585122381, 0),
					NotAfter:  time.Unix(9999999999, 0),
				},
				claims: &ZTSAccessTokenClaim{
					BaseClaim: BaseClaim{
						StandardClaims: jwt.StandardClaims{
							Subject:   "domain.tenant.service",
							IssuedAt:  1585122381,
							ExpiresAt: 9999999999,
							Issuer:    "https://zts.athenz.io",
							Audience:  "domain.provider",
						},
					},
					ClientID: "domain.tenant.service",
					Confirm:  map[string]string{"x5t#S256": "dummy"},
				},
			},
		},
		{
			name: "verify cert principal fail, CommonName is nil",
			fields: fields{
				jwkp: jwk.Provider(func(kid string) interface{} {
					return LoadRSAPublicKeyFromDisk("./asserts/public.pem")
				}),
				enableMTLSCertificateBoundAccessToken: true,
				clientCertificateOffsetSeconds:        3600,
			},
			args: args{
				cert: &x509.Certificate{
					Subject: pkix.Name{
						CommonName: "", // empty common name
					},
				},
				claims: &ZTSAccessTokenClaim{
					BaseClaim: BaseClaim{
						StandardClaims: jwt.StandardClaims{
							Subject:   "domain.tenant.service",
							IssuedAt:  1585122381,
							ExpiresAt: 9999999999,
							Issuer:    "https://zts.athenz.io",
							Audience:  "domain.provider",
						},
					},
					ClientID: "domain.tenant.service",
					Confirm:  map[string]string{"x5t#S256": "dummy"},
				},
			},
			wantErr: true,
		},
		{
			name: "verify cert principal fail, CommonName is empty",
			fields: fields{
				jwkp: jwk.Provider(func(kid string) interface{} {
					return LoadRSAPublicKeyFromDisk("./asserts/public.pem")
				}),
				enableMTLSCertificateBoundAccessToken: true,
				clientCertificateOffsetSeconds:        3600,
			},
			args: args{
				cert: &x509.Certificate{
					Subject: pkix.Name{
						CommonName: "domain.tenant.service",
					},
				},
				claims: &ZTSAccessTokenClaim{
					ClientID: "", // empty client id
				},
			},
			wantErr: true,
		},
		{
			name: "verify cert principal fail, ClientID is empty",
			fields: fields{
				jwkp: jwk.Provider(func(kid string) interface{} {
					return LoadRSAPublicKeyFromDisk("./asserts/public.pem")
				}),
				enableMTLSCertificateBoundAccessToken: true,
				clientCertificateOffsetSeconds:        3600,
			},
			args: args{
				cert: &x509.Certificate{
					Subject: pkix.Name{
						CommonName: "domain.tenant.service",
					},
				},
				claims: &ZTSAccessTokenClaim{
					ClientID: "",
				},
			},
			wantErr: true,
		},
		{
			name: "verify cert principal fail, principal mismatch",
			fields: fields{
				jwkp: jwk.Provider(func(kid string) interface{} {
					return LoadRSAPublicKeyFromDisk("./asserts/public.pem")
				}),
				enableMTLSCertificateBoundAccessToken: true,
				clientCertificateOffsetSeconds:        3600,
			},
			args: args{
				cert: &x509.Certificate{
					Subject: pkix.Name{
						CommonName: "domain.tenant.a",
					},
				},
				claims: &ZTSAccessTokenClaim{
					ClientID: "domain.tenant.b",
				},
			},
			wantErr: true,
		},
		{
			name: "verify cert principal fail, certificate that was generated before the token",
			fields: fields{
				jwkp: jwk.Provider(func(kid string) interface{} {
					return LoadRSAPublicKeyFromDisk("./asserts/public.pem")
				}),
				enableMTLSCertificateBoundAccessToken: true,
				clientCertificateGoBackSeconds:        3600,
				clientCertificateOffsetSeconds:        3600,
			},
			args: args{
				cert: &x509.Certificate{
					Subject: pkix.Name{
						CommonName: "domain.tenant.service",
					},
					NotBefore: time.Unix(1585122381-3600-100, 0), // token's IssuedAt - 3600(clientCertificateGoBackSeconds) - 100
				},
				claims: &ZTSAccessTokenClaim{
					ClientID: "domain.tenant.service",
					BaseClaim: BaseClaim{
						StandardClaims: jwt.StandardClaims{
							IssuedAt: 1585122381,
						},
					},
				},
			},

			wantErr: true,
		},
		{
			name: "verify cert principal fail, certificate that was generated after the clientCertificateOffsetSeconds",
			fields: fields{
				jwkp: jwk.Provider(func(kid string) interface{} {
					return LoadRSAPublicKeyFromDisk("./asserts/public.pem")
				}),
				enableMTLSCertificateBoundAccessToken: true,
				clientCertificateGoBackSeconds:        3600,
				clientCertificateOffsetSeconds:        3600,
			},
			args: args{
				cert: &x509.Certificate{
					Subject: pkix.Name{
						CommonName: "domain.tenant.service",
					},
					NotBefore: time.Unix(1585122381-3600+3600+100, 0), // token's IssuedAt - 3600(clientCertificateGoBackSeconds) +3600(clientCertificateOffsetSeconds) + 100
				},
				claims: &ZTSAccessTokenClaim{
					ClientID: "domain.tenant.service",
					BaseClaim: BaseClaim{
						StandardClaims: jwt.StandardClaims{
							IssuedAt: 1585122381,
						},
					},
				},
			},

			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &rtp{
				pkp:                                   tt.fields.pkp,
				jwkp:                                  tt.fields.jwkp,
				enableMTLSCertificateBoundAccessToken: tt.fields.enableMTLSCertificateBoundAccessToken,
				clientCertificateGoBackSeconds:        tt.fields.clientCertificateGoBackSeconds,
				clientCertificateOffsetSeconds:        tt.fields.clientCertificateOffsetSeconds,
			}
			if err := r.validateCertPrincipal(tt.args.cert, tt.args.claims); (err != nil) != tt.wantErr {
				t.Errorf("rtp.validateCertPrincipal() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
