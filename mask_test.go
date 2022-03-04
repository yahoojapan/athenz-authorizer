/*
Copyright (C)  2022 Yahoo Japan Corporation Athenz team.

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

package authorizerd

import (
	"testing"
)

func Test_maskCacheKey(t *testing.T) {
	type args struct {
		key string
		tok string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "normal key, normal token",
			args: args{
				key: "tok36:key35",
				tok: "tok36",
			},
			want: ":key35",
		},
		{
			name: "normal key, empty token",
			args: args{
				key: ":key44",
				tok: "",
			},
			want: ":key44",
		},
		{
			name: "empty key, normal token",
			args: args{
				key: "tok53",
				tok: "tok53",
			},
			want: "",
		},
		{
			name: "empty key, empty token",
			args: args{
				key: "",
				tok: "",
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := maskCacheKey(tt.args.key, tt.args.tok); got != tt.want {
				t.Errorf("maskCacheKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_maskToken(t *testing.T) {
	type args struct {
		m   mode
		tok string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "unknown token",
			args: args{
				m:   0,
				tok: "",
			},
			want: "mask token error: unknown token",
		},
		{
			name: "role token, empty token",
			args: args{
				m:   roleToken,
				tok: "",
			},
			want: "mask token error: invalid role token",
		},
		{
			name: "role token, invalid token",
			args: args{
				m:   roleToken,
				tok: "invalid role token 105",
			},
			want: "mask token error: invalid role token",
		},
		{
			name: "role token, normal token",
			args: args{
				m:   roleToken,
				tok: "v=Z1;d=domain;r=role;p=principal;s=signature_113",
			},
			want: "v=Z1;d=domain;r=role;p=principal",
		},
		{
			name: "access token, empty token",
			args: args{
				m:   accessToken,
				tok: "",
			},
			want: "mask token error: invalid access token",
		},
		{
			name: "access token, invalid token",
			args: args{
				m:   accessToken,
				tok: "invalid access token 129",
			},
			want: "mask token error: invalid access token",
		},
		{
			name: "access token, normal token",
			args: args{
				m:   accessToken,
				tok: "header.body.signature_137",
			},
			want: "header.body",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := maskToken(tt.args.m, tt.args.tok); got != tt.want {
				t.Errorf("maskToken() = %v, want %v", got, tt.want)
			}
		})
	}
}
