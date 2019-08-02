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

package url

import (
	"testing"
)

func TestTrimHTTPScheme(t *testing.T) {
	type args struct {
		urlStr string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "empty string",
			args: args{
				urlStr: "",
			},
			want: "",
		},
		{
			name: "no scheme success",
			args: args{
				urlStr: "www.athenz.com/path",
			},
			want: "www.athenz.com/path",
		},
		{
			name: "no scheme with port number success",
			args: args{
				urlStr: "www.athenz.com:8080/path",
			},
			want: "www.athenz.com:8080/path",
		},
		{
			name: "trim HTTP scheme success",
			args: args{
				urlStr: "http://www.athenz.com/path",
			},
			want: "www.athenz.com/path",
		},
		{
			name: "trim HTTPS scheme success",
			args: args{
				urlStr: "https://www.athenz.com/path/",
			},
			want: "www.athenz.com/path/",
		},
		{
			name: "trim HTTPS scheme with port number success",
			args: args{
				urlStr: "https://www.athenz.com:8080/path/",
			},
			want: "www.athenz.com:8080/path/",
		},
		{
			name: "non-http supported scheme",
			args: args{
				urlStr: "ftp://www.athenz.com/path",
			},
			want: "ftp://www.athenz.com/path",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TrimHTTPScheme(tt.args.urlStr)
			if got != tt.want {
				t.Errorf("TrimHTTPScheme() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasScheme(t *testing.T) {
	type args struct {
		url string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "no schema",
			args: args{
				url: "www.athenz.com/path",
			},
			want: false,
		},
		{
			name: "with schema",
			args: args{
				url: "ftp://www.athenz.com/path",
			},
			want: true,
		},
		{
			name: "with schema",
			args: args{
				url: "a0+-.://www.athenz.com/path",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HasScheme(tt.args.url); got != tt.want {
				t.Errorf("HasScheme() = %v, want %v", got, tt.want)
			}
		})
	}
}
