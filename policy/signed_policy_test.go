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
	"fmt"
	"testing"
	"time"

	"github.com/ardielle/ardielle-go/rdl"
	"github.com/kpango/fastime"
	"github.com/pkg/errors"
	authcore "github.com/yahoo/athenz/libs/go/zmssvctoken"
	"github.com/yahoo/athenz/utils/zpe-updater/util"
	"github.com/yahoojapan/athenz-authorizer/v5/pubkey"
)

func TestSignedPolicy_Verify(t *testing.T) {
	type fields struct {
		DomainSignedPolicyData util.DomainSignedPolicyData
	}
	type args struct {
		pkp pubkey.Provider
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr error
	}{
		{
			name: "verify success",
			fields: fields{
				DomainSignedPolicyData: util.DomainSignedPolicyData{
					KeyId:     "1",
					Signature: "dummySignature",
					SignedPolicyData: &util.SignedPolicyData{
						ZmsKeyId:     "1",
						ZmsSignature: "dummyZmsSign",
						PolicyData: &util.PolicyData{
							Domain: "dummy",
						},
						Expires: &rdl.Timestamp{
							Time: fastime.Now().Add(time.Hour),
						},
					},
				},
			},
			args: args{
				pkp: func(pubkey.AthenzEnv, string) authcore.Verifier {
					return VerifierMock{
						VerifyFunc: func(d, s string) error {
							if d == "" || s == "" {
								return fmt.Errorf("empty data or sign, data: %v, sign: %v", d, s)
							}
							return nil
						},
					}
				},
			},
		},
		{
			name: "no policy data",
			fields: fields{
				DomainSignedPolicyData: util.DomainSignedPolicyData{
					SignedPolicyData: nil,
				},
			},
			args: args{
				pkp: func(e pubkey.AthenzEnv, id string) authcore.Verifier {
					if e == pubkey.EnvZTS {
						return nil
					}
					return VerifierMock{
						VerifyFunc: func(d, s string) error {
							return nil
						},
					}
				},
			},
			wantErr: errors.New("no policy data"),
		},
		{
			name: "policy without expiry",
			fields: fields{
				DomainSignedPolicyData: util.DomainSignedPolicyData{
					SignedPolicyData: &util.SignedPolicyData{
						Expires: nil,
					},
				},
			},
			args: args{
				pkp: func(e pubkey.AthenzEnv, id string) authcore.Verifier {
					if e == pubkey.EnvZTS {
						return nil
					}
					return VerifierMock{
						VerifyFunc: func(d, s string) error {
							return nil
						},
					}
				},
			},
			wantErr: errors.New("policy without expiry"),
		},
		{
			name: "policy already expired",
			fields: fields{
				DomainSignedPolicyData: util.DomainSignedPolicyData{
					SignedPolicyData: &util.SignedPolicyData{
						Expires: &rdl.Timestamp{
							Time: time.Time{},
						},
					},
				},
			},
			args: args{
				pkp: func(e pubkey.AthenzEnv, id string) authcore.Verifier {
					if e == pubkey.EnvZTS {
						return nil
					}
					return VerifierMock{
						VerifyFunc: func(d, s string) error {
							return nil
						},
					}
				},
			},
			wantErr: errors.New("policy already expired at 0001-01-01 00:00:00 +0000 UTC"),
		},
		{
			name: "zts key not found",
			fields: fields{
				DomainSignedPolicyData: util.DomainSignedPolicyData{
					SignedPolicyData: &util.SignedPolicyData{
						Expires: &rdl.Timestamp{
							Time: fastime.Now().Add(time.Hour),
						},
					},
				},
			},
			args: args{
				pkp: func(e pubkey.AthenzEnv, id string) authcore.Verifier {
					if e == pubkey.EnvZTS {
						return nil
					}
					return VerifierMock{
						VerifyFunc: func(d, s string) error {
							return nil
						},
					}
				},
			},
			wantErr: errors.New("zts key not found"),
		},
		{
			name: "error verify signed policy data",
			fields: fields{
				DomainSignedPolicyData: util.DomainSignedPolicyData{
					Signature: "dummyZtsSignature",
					SignedPolicyData: &util.SignedPolicyData{
						Expires: &rdl.Timestamp{
							Time: fastime.Now().Add(time.Hour),
						},
					},
				},
			},
			args: args{
				pkp: func(e pubkey.AthenzEnv, kid string) authcore.Verifier {
					return VerifierMock{
						VerifyFunc: func(d, s string) error {
							if s == "dummyZtsSignature" {
								return fmt.Errorf("dummy error")
							}
							return nil
						},
					}
				},
			},
			wantErr: errors.New("error verify signature: dummy error"),
		},
		{
			name: "zms key not found",
			fields: fields{
				DomainSignedPolicyData: util.DomainSignedPolicyData{
					SignedPolicyData: &util.SignedPolicyData{
						Expires: &rdl.Timestamp{
							Time: fastime.Now().Add(time.Hour),
						},
					},
				},
			},
			args: args{
				pkp: func(e pubkey.AthenzEnv, id string) authcore.Verifier {
					if e == pubkey.EnvZMS {
						return nil
					}
					return VerifierMock{
						VerifyFunc: func(d, s string) error {
							return nil
						},
					}
				},
			},
			wantErr: errors.New("zms key not found"),
		},
		{
			name: "error verify policy data",
			fields: fields{
				DomainSignedPolicyData: util.DomainSignedPolicyData{
					SignedPolicyData: &util.SignedPolicyData{
						ZmsSignature: "dummyZmsSignature",
						Expires: &rdl.Timestamp{
							Time: fastime.Now().Add(time.Hour),
						},
					},
				},
			},
			args: args{
				pkp: func(e pubkey.AthenzEnv, kid string) authcore.Verifier {
					return VerifierMock{
						VerifyFunc: func(d, s string) error {
							if s == "dummyZmsSignature" {
								return fmt.Errorf("dummy error")
							}
							return nil
						},
					}
				},
			},
			wantErr: errors.New("error verify zms signature: dummy error"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &SignedPolicy{
				DomainSignedPolicyData: tt.fields.DomainSignedPolicyData,
			}
			err := s.Verify(tt.args.pkp)
			if err == nil {
				if tt.wantErr != nil {
					t.Errorf("SignedPolicy.Verify() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else {
				if tt.wantErr == nil {
					t.Errorf("SignedPolicy.Verify() error = %v, wantErr %v", err, tt.wantErr)
				} else if err.Error() != tt.wantErr.Error() {
					t.Errorf("SignedPolicy.Verify() error = %v, wantErr %v", err, tt.wantErr)
				}
			}

		})
	}
}
