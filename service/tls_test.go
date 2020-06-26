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
package service

import (
	"fmt"
	"strings"
	"testing"
)

func TestNewX509CertPool(t *testing.T) {
	type args struct {
		path string
	}
	type test struct {
		name    string
		args    args
		wantErr error
	}

	tests := []test{
		{
			name: "Get CA cert pool",
			args: args{
				path: "../test/data/dummy_CA.pem",
			},
		},
		{
			name: "Missing CA file",
			args: args{
				path: "../test/data/non_existing_CA_file.pem",
			},
			wantErr: fmt.Errorf("no such file or directory"),
		},
		{
			name: "Argument not specified",
			args: args{
				path: "",
			},
			wantErr: fmt.Errorf("no such file or directory"),
		},
		{
			name: "Request with invalid CA file",
			args: args{
				path: "../test/data/invalid_dummy_CA.pem",
			},
			wantErr: fmt.Errorf("Certification Failed"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewX509CertPool(tt.args.path)
			if err != nil && tt.wantErr == nil {
				t.Errorf("NewX509CertPool() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("want error: %v  got: %v", tt.wantErr, err)
					return
				}
				if !strings.Contains(err.Error(), tt.wantErr.Error()) {
					t.Errorf("NewX509CertPool() error: %v, want: %v", err, tt.wantErr)
					return
				}
			} else {
				if got == nil {
					t.Errorf("CertPool should not be empty: got: %v", got)
					return
				}
			}
		})
	}
}
