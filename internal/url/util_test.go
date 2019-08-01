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

import "testing"

func TestTrimHTTPScheme(t *testing.T) {
	type args struct {
		urlStr string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "empty string",
			args: args{
				urlStr: "",
			},
			want:    "",
			wantErr: false,
		},
		{
			name: "no scheme success",
			args: args{
				urlStr: "www.athenz.com/path",
			},
			want:    "www.athenz.com/path",
			wantErr: false,
		},
		{
			name: "trim HTTP scheme success",
			args: args{
				urlStr: "http://www.athenz.com/path",
			},
			want:    "www.athenz.com/path",
			wantErr: false,
		},
		{
			name: "trim HTTPS scheme success",
			args: args{
				urlStr: "https://www.athenz.com/path/",
			},
			want:    "www.athenz.com/path/",
			wantErr: false,
		},
		{
			name: "error, unsupported scheme",
			args: args{
				urlStr: "ftp://www.athenz.com/path",
			},
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := TrimHTTPScheme(tt.args.urlStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("TrimHTTPScheme() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("TrimHTTPScheme() = %v, want %v", got, tt.want)
			}
		})
	}
}
