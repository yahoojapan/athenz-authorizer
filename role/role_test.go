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
	"fmt"
	"reflect"
	"testing"
	"time"

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
					ExpiryTime: time.Now().Add(time.Hour),
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
					ExpiryTime: time.Now().Add(-1 * time.Hour),
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
					ExpiryTime: time.Now().Add(time.Hour),
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
					ExpiryTime: time.Now().Add(time.Hour),
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
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *Claim
		wantErr bool
	}{
		// TODO: Add test cases.
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
				t.Errorf("rtp.ParseAndValidateRoleJWT() = %v, want %v", got, tt.want)
			}
		})
	}
}
