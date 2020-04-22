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

package access

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"reflect"
	"testing"
	"time"

	"github.com/pkg/errors"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/yahoojapan/athenz-authorizer/v2/jwk"
)

// test data is generated by `access/asserts/private.pem`

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
			want: &atp{
				nil,
				false,
				0,
				0,
				false,
				nil,
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
			want: &atp{
				nil,
				true,
				0,
				0,
				false,
				nil,
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

func Test_rtp_keyFunc(t *testing.T) {
	type fields struct {
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
			r := &atp{
				jwkp: tt.fields.jwkp,
			}
			got, err := r.keyFunc(tt.args.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("atp.keyFunc() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("atp.keyFunc() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_rtp_ParseAndValidateOAuth2AccessToken(t *testing.T) {
	type fields struct {
		jwkp                                  jwk.Provider
		enableMTLSCertificateBoundAccessToken bool
		enableVerifyClientID                  bool
		authorizedClientIDs                   map[string][]string
	}
	type args struct {
		cred string
		cert *x509.Certificate
	}
	type test struct {
		name    string
		fields  fields
		args    args
		want    *OAuth2AccessTokenClaim
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
				want: func() *OAuth2AccessTokenClaim {
					c := OAuth2AccessTokenClaim{
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
				name: "verify access token success, verify client_id",
				fields: fields{
					jwkp: jwk.Provider(func(kid string) interface{} {
						return LoadRSAPublicKeyFromDisk("./asserts/public.pem")
					}),
					enableVerifyClientID: true,
					authorizedClientIDs: map[string][]string{
						"domain.tenant.service": []string{
							"domain.tenant.service",
						},
					},
				},
				args: args{
					cred: `eyJraWQiOiIwIiwidHlwIjoiYXQrand0IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJkb21haW4udGVuYW50LnNlcnZpY2UiLCJpYXQiOjE1ODUxMjIzODEsImV4cCI6OTk5OTk5OTk5OSwiaXNzIjoiaHR0cHM6Ly96dHMuYXRoZW56LmlvIiwiYXVkIjoiZG9tYWluLnByb3ZpZGVyIiwiYXV0aF90aW1lIjoxNTg1MTIyMzgxLCJ2ZXIiOjEsInNjcCI6WyJhZG1pbiIsInVzZXIiXSwidWlkIjoiZG9tYWluLnRlbmFudC5zZXJ2aWNlIiwiY2xpZW50X2lkIjoiZG9tYWluLnRlbmFudC5zZXJ2aWNlIn0.Fu3hMaFRHteJEkn9bhz0Qlxl1Mwga-xkXDPoke_amo1I-J0sw9CMrVLpW1WFXsWD2dehev-vawxsl3mO_xoz0Z1Wom6rSJJOqTFDiIzcbYNVuD2CcobdoddPH2npSoKYNT3MypVF9Wjt9KMnxBEuy-zOv9Lf6xjvbqcKF6RCmlWjQlzWGwqjWM7JcNEtLaWB8n1yQ31RvL4o1ZpKlbha5F1jjvCu-ifzhmQ64p9Sl3NBnenik6J0i9V-f_I9lK5ycQjcMaD0gBb3XCFVamUW_iP-YY2JJMWGW6LJNC_3ywH40fQt8Om9a-kFjpPCaztPI0poobSMTe1ISMXV-lROMw`,
					cert: func() *x509.Certificate {
						return LoadX509CertFromDisk("./asserts/dummyClient.crt")
					}(),
				},
				want: func() *OAuth2AccessTokenClaim {
					c := OAuth2AccessTokenClaim{
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
				want: func() *OAuth2AccessTokenClaim {
					c := OAuth2AccessTokenClaim{
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
				name: "verify access token fail, unauthorized client_id",
				fields: fields{
					jwkp: jwk.Provider(func(kid string) interface{} {
						return LoadRSAPublicKeyFromDisk("./asserts/public.pem")
					}),
					enableVerifyClientID: true,
					authorizedClientIDs: map[string][]string{
						"unauthorizedPrincipal": {
							"unauthorizedClientID",
						},
					},
				},
				args: args{
					cred: `eyJraWQiOiIwIiwidHlwIjoiYXQrand0IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJkb21haW4udGVuYW50LnNlcnZpY2UiLCJpYXQiOjE1ODUxMjIzODEsImV4cCI6OTk5OTk5OTk5OSwiaXNzIjoiaHR0cHM6Ly96dHMuYXRoZW56LmlvIiwiYXVkIjoiZG9tYWluLnByb3ZpZGVyIiwiYXV0aF90aW1lIjoxNTg1MTIyMzgxLCJ2ZXIiOjEsInNjcCI6WyJhZG1pbiIsInVzZXIiXSwidWlkIjoiZG9tYWluLnRlbmFudC5zZXJ2aWNlIiwiY2xpZW50X2lkIjoiZG9tYWluLnRlbmFudC5zZXJ2aWNlIn0.Fu3hMaFRHteJEkn9bhz0Qlxl1Mwga-xkXDPoke_amo1I-J0sw9CMrVLpW1WFXsWD2dehev-vawxsl3mO_xoz0Z1Wom6rSJJOqTFDiIzcbYNVuD2CcobdoddPH2npSoKYNT3MypVF9Wjt9KMnxBEuy-zOv9Lf6xjvbqcKF6RCmlWjQlzWGwqjWM7JcNEtLaWB8n1yQ31RvL4o1ZpKlbha5F1jjvCu-ifzhmQ64p9Sl3NBnenik6J0i9V-f_I9lK5ycQjcMaD0gBb3XCFVamUW_iP-YY2JJMWGW6LJNC_3ywH40fQt8Om9a-kFjpPCaztPI0poobSMTe1ISMXV-lROMw`,
				},
				wantErr: true,
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
		func() test {
			return test{
				name: "verify certificate bound access token fail, empty cnf (\"cnf\": \"\")",
				fields: fields{
					jwkp: jwk.Provider(func(kid string) interface{} {
						return LoadRSAPublicKeyFromDisk("./asserts/public.pem")
					}),
					enableMTLSCertificateBoundAccessToken: true,
				},
				args: args{
					cred: `eyJraWQiOiIwIiwidHlwIjoiYXQrand0IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJkb21haW4udGVuYW50LnNlcnZpY2UiLCJpYXQiOjE1ODUxMjIzODEsImV4cCI6OTk5OTk5OTk5OSwiaXNzIjoiaHR0cHM6Ly96dHMuYXRoZW56LmlvIiwiYXVkIjoiZG9tYWluLnByb3ZpZGVyIiwiYXV0aF90aW1lIjoxNTg1MTIyMzgxLCJ2ZXIiOjEsInNjcCI6WyJhZG1pbiIsInVzZXIiXSwidWlkIjoiZG9tYWluLnRlbmFudC5zZXJ2aWNlIiwiY2xpZW50X2lkIjoiZG9tYWluLnRlbmFudC5zZXJ2aWNlIiwiY25mIjoiIn0.WMZ9THmblO-txpF75pLCiv58c9gfgqBRTssOH8Yx7WlXN9Z5jyOebIahlA3ULqiRiwaAd_5eXYRxS4iIFKGvThNPiVjocfIGq5Mj7mnkqM672N0zzbd79thI9aHieJvr7UB6yjSIkJSfRD-c36tmIFMrPkSQw-Rk1mUUTFTW1O40o1ZDZeK4UZP-plcJJ7MlDk7pCeMShEiKa-7iYxQsfSJqszeNqJEYPbMDudaqKhmu18m_Yo7Ac7Ur8ufaD3kUbOViV6Y4wJCGthtzeasx0lQ4b4ymqPgYF53RgdkoWVwwVCqw4XJPgbIwx8vPQ2vYY0zrhq_PSn251ZyI--pNJA`,
					cert: func() *x509.Certificate {
						return LoadX509CertFromDisk("./asserts/dummyClient.crt")
					}(),
				},
				wantErr: true,
			}
		}(),
		func() test {
			return test{
				name: "verify certificate bound access token fail, empty cnf (cnf: \"cnf\": {\"x5t#S256\": {}})",
				fields: fields{
					jwkp: jwk.Provider(func(kid string) interface{} {
						return LoadRSAPublicKeyFromDisk("./asserts/public.pem")
					}),
					enableMTLSCertificateBoundAccessToken: true,
				},
				args: args{
					cred: `eyJraWQiOiIwIiwidHlwIjoiYXQrand0IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJkb21haW4udGVuYW50LnNlcnZpY2UiLCJpYXQiOjE1ODUxMjIzODEsImV4cCI6OTk5OTk5OTk5OSwiaXNzIjoiaHR0cHM6Ly96dHMuYXRoZW56LmlvIiwiYXVkIjoiZG9tYWluLnByb3ZpZGVyIiwiYXV0aF90aW1lIjoxNTg1MTIyMzgxLCJ2ZXIiOjEsInNjcCI6WyJhZG1pbiIsInVzZXIiXSwidWlkIjoiZG9tYWluLnRlbmFudC5zZXJ2aWNlIiwiY2xpZW50X2lkIjoiZG9tYWluLnRlbmFudC5zZXJ2aWNlIiwiY25mIjp7Ing1dCNTMjU2Ijp7fX19.jil95otB9yKJCUTrpbl5h592HKQYDquhz5vSfeAv3fcmFkvSAIcwizKPlWfW2g3eF_VZVu3WRgJyHCwIfWKrOTqdGGJYJs1QmkDAYhjkpgsLCBVXAM63dBIGKRkpt2eO4biqPfjynE--RcJLK1qMVpoWUaQW0QnM5XjjVpgcJtR1l3sjnUXGO4J2L0Q_CAyHSoQvd00jlWA72c32V2L10mQ5BXtEaaEgC8nVc6sdLtAhfUOvyx7xhRFuWl9VL-OO8Z2_5jx1goF2E6Icejmjk5gtKTJa9Wo-ck-P4stphWbNQEpfia6JJXE3y-LKBvdZKmCJhVpKUY_ZWSOLaNQpgA`,
					cert: func() *x509.Certificate {
						return LoadX509CertFromDisk("./asserts/dummyClient.crt")
					}(),
				},
				wantErr: true,
			}
		}(),
		func() test {
			return test{
				name: "verify certificate bound access token fail, empty cnf (\"cnf\": {})",
				fields: fields{
					jwkp: jwk.Provider(func(kid string) interface{} {
						return LoadRSAPublicKeyFromDisk("./asserts/public.pem")
					}),
					enableMTLSCertificateBoundAccessToken: true,
				},
				args: args{
					cred: `eyJraWQiOiIwIiwidHlwIjoiYXQrand0IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJkb21haW4udGVuYW50LnNlcnZpY2UiLCJpYXQiOjE1ODUxMjIzODEsImV4cCI6OTk5OTk5OTk5OSwiaXNzIjoiaHR0cHM6Ly96dHMuYXRoZW56LmlvIiwiYXVkIjoiZG9tYWluLnByb3ZpZGVyIiwiYXV0aF90aW1lIjoxNTg1MTIyMzgxLCJ2ZXIiOjEsInNjcCI6WyJhZG1pbiIsInVzZXIiXSwidWlkIjoiZG9tYWluLnRlbmFudC5zZXJ2aWNlIiwiY2xpZW50X2lkIjoiZG9tYWluLnRlbmFudC5zZXJ2aWNlIiwiY25mIjp7fX0.cqTRMqS5blcZ0xGch0zLsn7Y5CEXdgnHwCO2kAPt5U2pSQeiWHIk-wamh755vflfc-amtNsJE0RUWPWEIYNtmyHb3sk5aeJrG0N7zor58o1s-sfqfgm2l8efREmLw08ArY6xx_528FvTAcq7y3vjzpqeWS46079IojcoyuST3dXGjQUcOv1U1JrRYAd1tGxvz7UL0JzLXwCFUsJx5qwePArbU_GfjgB8-_-u2t4a3NCxkAb-ZZ-pxGfbfiRzOiflt_fC0TctzFyF_zGIMCW0TYhsHU2c-iA9Wi8_yfT3qbVpWjT0ud_b76kNXoBGzZ4Y17ka41bL6g0I_g3u5G-8mw`,
					cert: func() *x509.Certificate {
						return LoadX509CertFromDisk("./asserts/dummyClient.crt")
					}(),
				},
				wantErr: true,
			}
		}(),
		{
			name: "verify certificate bound access token success, verify client_id fail, verify thumbprint success",
			fields: fields{
				jwkp: jwk.Provider(func(kid string) interface{} {
					return LoadRSAPublicKeyFromDisk("./asserts/public.pem")
				}),
				enableMTLSCertificateBoundAccessToken: true,
				enableVerifyClientID:                  true,
				authorizedClientIDs: map[string][]string{
					"fail.commmon-name": {"fail.client_id"},
				},
			},
			args: args{
				cred: `eyJraWQiOiIwIiwidHlwIjoiYXQrand0IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJkb21haW4udGVuYW50LnNlcnZpY2UiLCJpYXQiOjE1ODUxMjIzODEsImV4cCI6OTk5OTk5OTk5OSwiaXNzIjoiaHR0cHM6Ly96dHMuYXRoZW56LmlvIiwiYXVkIjoiZG9tYWluLnByb3ZpZGVyIiwiYXV0aF90aW1lIjoxNTg1MTIyMzgxLCJ2ZXIiOjEsInNjcCI6WyJhZG1pbiIsInVzZXIiXSwidWlkIjoiZG9tYWluLnRlbmFudC5zZXJ2aWNlIiwiY2xpZW50X2lkIjoiZG9tYWluLnRlbmFudC5zZXJ2aWNlIiwiY25mIjp7Ing1dCNTMjU2IjoiMmp0ODJmMnVNOGpFMkxNY2I0ZXJoaFRjLXV5MXlCMWlFeXA1TW5JNXVGNCJ9fQ.OyotreYeMFDTpDaIoPVnEBY1RnVuzRortfRKnkOfZUEv1wSSmgSPxBE9IfgxD57kCQUJtO4GUBUWX_DrIb8BMMVUaDlws6UTncaCUdTt_lJXuIZilh7vIA5oiRTtpADJrZUS3kH2ln6qTXa1QTeevg5qdfORya7ILiHdJUmQXbb9vndYcS4-4E3Xr7rqj7cD67rvySM8YIOsaMn2UX237VUo2rcs40XuHH6WCFfix4xxmgTxS7zr_uowqxpXrgpc0g_eT4On9gnuTDcAzwVy7qbgWMcEO-UrhV_FiPzIRj5RZFZBeHjNeU2QAAT-LAw7S6YJtlPpijfTM9qx6xC0GA`,
				cert: func() *x509.Certificate {
					return LoadX509CertFromDisk("./asserts/dummyClient.crt")
				}(),
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "verify certificate bound access token success, verify client_id success, verify thumbprint fail",
			fields: fields{
				jwkp: jwk.Provider(func(kid string) interface{} {
					return LoadRSAPublicKeyFromDisk("./asserts/public.pem")
				}),
				enableMTLSCertificateBoundAccessToken: true,
				enableVerifyClientID:                  true,
				authorizedClientIDs: map[string][]string{
					"domain.tenant.service": {"domain.tenant.service"},
				},
			},
			args: args{
				cred: `eyJraWQiOiIwIiwidHlwIjoiYXQrand0IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJkb21haW4udGVuYW50LnNlcnZpY2UiLCJpYXQiOjE1ODUxMjIzODEsImV4cCI6OTk5OTk5OTk5OSwiaXNzIjoiaHR0cHM6Ly96dHMuYXRoZW56LmlvIiwiYXVkIjoiZG9tYWluLnByb3ZpZGVyIiwiYXV0aF90aW1lIjoxNTg1MTIyMzgxLCJ2ZXIiOjEsInNjcCI6WyJhZG1pbiIsInVzZXIiXSwidWlkIjoiZG9tYWluLnRlbmFudC5zZXJ2aWNlIiwiY2xpZW50X2lkIjoiZG9tYWluLnRlbmFudC5zZXJ2aWNlIiwiY25mIjp7Ing1dCNTMjU2IjoiZmFpbC5jb25maXJtIn19.m7dfG-3YCMTADYzc641jAP-jAxWnfpsb0EOL6lew-yI2cdzfhhSyX7Htiru16hfZzTZ-O5vM4UWitP89_hVYa4ycA225WIFXJPyAe3aeVzJXCIzUCGvUs0pxsNVevhwjIzJFS6t7TT593-yX5TeG4eVZpIVXE1DK1tMllNx1dBNJ7ta1MEpsd8_V5cLY4uw8Fd-rxRE9RhnmLFVnycw2Q6wQ-OljH1To3wiVG69qQyHCzy3anL-TZ8IgYinixraXNfdBE4ePyJztqG_Ug_24pxIpczRSwBmkvwULfvk7baYIZ-1YHhhWpBofbyEGGd-jCAH7SBsZLqR2bdfzvxUsKQ`,
				cert: func() *x509.Certificate {
					return LoadX509CertFromDisk("./asserts/dummyClient.crt")
				}(),
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &atp{
				jwkp:                                  tt.fields.jwkp,
				enableMTLSCertificateBoundAccessToken: tt.fields.enableMTLSCertificateBoundAccessToken,
				enableVerifyClientID:                  tt.fields.enableVerifyClientID,
				authorizedClientIDs:                   tt.fields.authorizedClientIDs,
			}
			got, err := r.ParseAndValidateOAuth2AccessToken(tt.args.cred, tt.args.cert)
			if (err != nil) != tt.wantErr {
				t.Errorf("atp.ParseAndValidateOAuth2AccessToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("atp.ParseAndValidateOAuth2AccessToken() = %+v, want %v", got, tt.want)
			}
		})
	}
}

func Test_rtp_validateClientID(t *testing.T) {
	type fields struct {
		jwkp                                  jwk.Provider
		enableMTLSCertificateBoundAccessToken bool
		enableVerifyClientID                  bool
		authorizedClientIDs                   map[string][]string
		clientCertificateGoBackSeconds        int64
		clientCertificateOffsetSeconds        int64
	}
	type args struct {
		cert   *x509.Certificate
		claims *OAuth2AccessTokenClaim
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr error
	}{
		{
			name: "verify client_id success",
			fields: fields{
				enableVerifyClientID: true,
				authorizedClientIDs: map[string][]string{
					"dummy cn1": []string{"dummy client_id1", "dummy client_id2"},
					"dummy cn2": []string{"dummy client_id1", "dummy client_id2"},
				},
			},
			args: args{
				cert: &x509.Certificate{
					Subject: pkix.Name{
						CommonName: "dummy cn2",
					},
				},
				claims: &OAuth2AccessTokenClaim{
					ClientID: "dummy client_id2",
				},
			},
			wantErr: nil,
		},
		{
			name: "verify client_id fail, cert is nil",
			fields: fields{
				enableVerifyClientID: true,
				authorizedClientIDs:  map[string][]string{},
			},
			args: args{
				cert: nil,
				claims: &OAuth2AccessTokenClaim{
					ClientID: "dummy client_id1",
				},
			},
			wantErr: errors.New("error mTLS client certificate is nil"),
		},
		{
			name: "verify client_id fail, claim is nil",
			fields: fields{
				enableVerifyClientID: true,
				authorizedClientIDs:  map[string][]string{},
			},
			args: args{
				cert: &x509.Certificate{
					Subject: pkix.Name{
						CommonName: "dummy cn2",
					},
				},
				claims: nil,
			},
			wantErr: errors.New("error claim of access token is nil"),
		},
		{
			name: "verify client_id fail, authorizedClientIDs is empty",
			fields: fields{
				enableVerifyClientID: true,
				authorizedClientIDs:  map[string][]string{},
			},
			args: args{
				cert: &x509.Certificate{
					Subject: pkix.Name{
						CommonName: "dummy cn1",
					},
				},
				claims: &OAuth2AccessTokenClaim{
					ClientID: "dummy client_id1",
				},
			},
			wantErr: errors.Errorf("error %v is not authorized %v", "dummy client_id1", "dummy cn1"),
		},
		{
			name: "verify client_id fail, authorizedClientIDs is nil",
			fields: fields{
				enableVerifyClientID: true,
				authorizedClientIDs:  nil,
			},
			args: args{
				cert: &x509.Certificate{
					Subject: pkix.Name{
						CommonName: "dummy cn1",
					},
				},
				claims: &OAuth2AccessTokenClaim{
					ClientID: "dummy client_id1",
				},
			},
			wantErr: errors.Errorf("error %v is not authorized %v", "dummy client_id1", "dummy cn1"),
		},
		{
			name: "verify client_id fail, not match",
			fields: fields{
				enableVerifyClientID: true,
				authorizedClientIDs: map[string][]string{
					"dummy cn1": []string{"dummy client_id1", "dummy client_id2"},
					"dummy cn2": []string{"dummy client_id1", "dummy client_id2"},
				},
			},
			args: args{
				cert: &x509.Certificate{
					Subject: pkix.Name{
						CommonName: "dummy cn3",
					},
				},
				claims: &OAuth2AccessTokenClaim{
					ClientID: "dummy client_id3",
				},
			},
			wantErr: errors.Errorf("error %v is not authorized %v", "dummy client_id3", "dummy cn3"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &atp{
				jwkp:                                  tt.fields.jwkp,
				enableMTLSCertificateBoundAccessToken: tt.fields.enableMTLSCertificateBoundAccessToken,
				enableVerifyClientID:                  tt.fields.enableVerifyClientID,
				authorizedClientIDs:                   tt.fields.authorizedClientIDs,
				clientCertificateGoBackSeconds:        tt.fields.clientCertificateGoBackSeconds,
				clientCertificateOffsetSeconds:        tt.fields.clientCertificateOffsetSeconds,
			}
			if err := r.validateClientID(tt.args.cert, tt.args.claims); (err != nil) != (err != tt.wantErr) {
				t.Errorf("atp.validateClientID() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_rtp_validateCertificateBoundAccessToken(t *testing.T) {
	type fields struct {
		jwkp                                  jwk.Provider
		enableMTLSCertificateBoundAccessToken bool
		clientCertificateGoBackSeconds        int64
		clientCertificateOffsetSeconds        int64
	}
	type args struct {
		cert   *x509.Certificate
		claims *OAuth2AccessTokenClaim
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
			name: "verify certificate bound access token success",
			fields: fields{
				enableMTLSCertificateBoundAccessToken: true,
			},
			args: args{
				cert: func() *x509.Certificate {
					return LoadX509CertFromDisk("./asserts/dummyClient.crt")
				}(),
				claims: &OAuth2AccessTokenClaim{
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
			name: "verify certificate bound access token success, refreshed certificate",
			fields: fields{
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
				claims: &OAuth2AccessTokenClaim{
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
			name: "verify certificate bound access token fail, cert is nil",
			fields: fields{
				enableMTLSCertificateBoundAccessToken: true,
			},
			args: args{
				cert: nil,
				claims: &OAuth2AccessTokenClaim{
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
			name: "verify certificate bound access token fail, claim is nil",
			fields: fields{
				enableMTLSCertificateBoundAccessToken: true,
			},
			args: args{
				cert:   &x509.Certificate{},
				claims: nil,
			},
			wantErr: true,
		},
		{
			name: "verify certificate bound access token fail, invalid confirmation claim",
			fields: fields{
				enableMTLSCertificateBoundAccessToken: true,
			},
			args: args{
				cert: func() *x509.Certificate {
					return LoadX509CertFromDisk("./asserts/dummyClient.crt")
				}(),
				claims: &OAuth2AccessTokenClaim{
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
					Confirm:  map[string]string{"x5t#S256": "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo"},
				},
			},
			wantErr: true,
		},
		{
			name: "verify certificate bound access token fail, no confirmation claim",
			fields: fields{
				enableMTLSCertificateBoundAccessToken: true,
			},
			args: args{
				cert: func() *x509.Certificate {
					return LoadX509CertFromDisk("./asserts/dummyClient.crt")
				}(),
				claims: &OAuth2AccessTokenClaim{
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
			name: "verify certificate bound access token fail, cnf check fail and no client_id",
			fields: fields{
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
				claims: &OAuth2AccessTokenClaim{
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
			r := &atp{
				jwkp:                                  tt.fields.jwkp,
				enableMTLSCertificateBoundAccessToken: tt.fields.enableMTLSCertificateBoundAccessToken,
				clientCertificateGoBackSeconds:        tt.fields.clientCertificateGoBackSeconds,
				clientCertificateOffsetSeconds:        tt.fields.clientCertificateOffsetSeconds,
			}
			if err := r.validateCertificateBoundAccessToken(tt.args.cert, tt.args.claims); (err != nil) != tt.wantErr {
				t.Errorf("atp.validateCertificateBoundAccessToken() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_rtp_validateCertPrincipal(t *testing.T) {
	type fields struct {
		jwkp                                  jwk.Provider
		enableMTLSCertificateBoundAccessToken bool
		clientCertificateGoBackSeconds        int64
		clientCertificateOffsetSeconds        int64
	}
	type args struct {
		cert   *x509.Certificate
		claims *OAuth2AccessTokenClaim
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
				claims: &OAuth2AccessTokenClaim{
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
				claims: &OAuth2AccessTokenClaim{
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
				enableMTLSCertificateBoundAccessToken: true,
				clientCertificateOffsetSeconds:        3600,
			},
			args: args{
				cert: &x509.Certificate{
					Subject: pkix.Name{
						CommonName: "", // empty common name
					},
				},
				claims: &OAuth2AccessTokenClaim{
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
				enableMTLSCertificateBoundAccessToken: true,
				clientCertificateOffsetSeconds:        3600,
			},
			args: args{
				cert: &x509.Certificate{
					Subject: pkix.Name{
						CommonName: "domain.tenant.service",
					},
				},
				claims: &OAuth2AccessTokenClaim{
					ClientID: "", // empty client id
				},
			},
			wantErr: true,
		},
		{
			name: "verify cert principal fail, ClientID is empty",
			fields: fields{
				enableMTLSCertificateBoundAccessToken: true,
				clientCertificateOffsetSeconds:        3600,
			},
			args: args{
				cert: &x509.Certificate{
					Subject: pkix.Name{
						CommonName: "domain.tenant.service",
					},
				},
				claims: &OAuth2AccessTokenClaim{
					ClientID: "",
				},
			},
			wantErr: true,
		},
		{
			name: "verify cert principal fail, principal mismatch",
			fields: fields{
				enableMTLSCertificateBoundAccessToken: true,
				clientCertificateOffsetSeconds:        3600,
			},
			args: args{
				cert: &x509.Certificate{
					Subject: pkix.Name{
						CommonName: "domain.tenant.a",
					},
				},
				claims: &OAuth2AccessTokenClaim{
					ClientID: "domain.tenant.b",
				},
			},
			wantErr: true,
		},
		{
			name: "verify cert principal fail, certificate that was generated before the token",
			fields: fields{
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
				claims: &OAuth2AccessTokenClaim{
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
				claims: &OAuth2AccessTokenClaim{
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
			r := &atp{
				jwkp:                                  tt.fields.jwkp,
				enableMTLSCertificateBoundAccessToken: tt.fields.enableMTLSCertificateBoundAccessToken,
				clientCertificateGoBackSeconds:        tt.fields.clientCertificateGoBackSeconds,
				clientCertificateOffsetSeconds:        tt.fields.clientCertificateOffsetSeconds,
			}
			if err := r.validateCertPrincipal(tt.args.cert, tt.args.claims); (err != nil) != tt.wantErr {
				t.Errorf("atp.validateCertPrincipal() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
