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
	"fmt"
	"io/ioutil"
	"reflect"
	"testing"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/kpango/fastime"
	authcore "github.com/yahoo/athenz/libs/go/zmssvctoken"
	"github.com/yahoojapan/athenz-authorizer/jwk"
	"github.com/yahoojapan/athenz-authorizer/pubkey"
)

func TestNew(t *testing.T) {
	type args struct {
		opts []Option
	}
	type test struct {
		name string
		args args
		want Processor
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
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := New(tt.args.opts...); !reflect.DeepEqual(got, tt.want) {
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
		want    *Claim
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
				want: func() *Claim {
					c := &Claim{}
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
