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
	"github.com/yahoojapan/athenz-policy-updater/config"
)

func TestNewRoleTokenParser(t *testing.T) {
	type args struct {
		prov config.PubKeyProvider
	}
	type test struct {
		name string
		args args
		want RoleTokenParser
	}
	tests := []test{
		func() test {
			/*		p := config.PubKeyProvider(func(config.AthenzEnv, string) authcore.Verifier {
					return nil
				})*/
			return test{
				name: "new success",
				args: args{
					nil,
				},
				want: &rtp{
					nil,
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewRoleTokenParser(tt.args.prov); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewRoleTokenParser() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_rtp_ParseAndValidateRoleToken(t *testing.T) {
	type fields struct {
		pkp config.PubKeyProvider
	}
	type args struct {
		tok string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *RoleToken
		wantErr bool
	}{
		{
			name: "parse validate success",
			fields: fields{
				pkp: func(config.AthenzEnv, string) authcore.Verifier {
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
			want: &RoleToken{
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
				pkp: func(config.AthenzEnv, string) authcore.Verifier {
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

func Test_rtp_parseRoleToken(t *testing.T) {
	type fields struct {
		pkp config.PubKeyProvider
	}
	type args struct {
		tok string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *RoleToken
		wantErr bool
	}{
		{
			name: "parse success",
			args: args{
				tok: "v=Z1;d=dummy.sidecartest;r=users;p=takumats.tenant.test;h=dummyhost;a=e55ee6ddc3e3c27c;t=1550463321;e=1550643321;k=0;i=172.16.168.25;s=dummysignature",
			},
			want: &RoleToken{
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
			got, err := r.parseRoleToken(tt.args.tok)
			if (err != nil) != tt.wantErr {
				t.Errorf("rtp.parseRoleToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("rtp.parseRoleToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_rtp_validate(t *testing.T) {
	type fields struct {
		pkp config.PubKeyProvider
	}
	type args struct {
		rt *RoleToken
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
				pkp: func(config.AthenzEnv, string) authcore.Verifier {
					return VerifierMock{
						VerifyFunc: func(string, string) error {
							return nil
						},
					}
				},
			},
			args: args{
				&RoleToken{
					ExpiryTime: time.Now().Add(time.Hour),
				},
			},
		},
		{
			name: "token expired",
			fields: fields{
				pkp: func(config.AthenzEnv, string) authcore.Verifier {
					return VerifierMock{
						VerifyFunc: func(string, string) error {
							return nil
						},
					}
				},
			},
			args: args{
				&RoleToken{
					ExpiryTime: time.Now().Add(-1 * time.Hour),
				},
			},
			wantErr: true,
		},
		{
			name: "validate error",
			fields: fields{
				pkp: func(config.AthenzEnv, string) authcore.Verifier {
					return VerifierMock{
						VerifyFunc: func(string, string) error {
							return fmt.Errorf("")
						},
					}
				},
			},
			args: args{
				&RoleToken{
					ExpiryTime: time.Now().Add(time.Hour),
				},
			},
			wantErr: true,
		},
		{
			name: "verifier not found",
			fields: fields{
				pkp: func(config.AthenzEnv, string) authcore.Verifier {
					return nil
				},
			},
			args: args{
				&RoleToken{
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
