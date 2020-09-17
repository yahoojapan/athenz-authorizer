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
package jwk

import (
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"

	urlutil "github.com/yahoojapan/athenz-authorizer/v5/internal/url"
)

func TestWithAthenzJwksURL(t *testing.T) {
	type args struct {
		url string
	}
	tests := []struct {
		name    string
		args    args
		want    *jwkd
		wantErr error
	}{
		{
			name: "empty string",
			args: args{
				"",
			},
			want:    &jwkd{athenzJwksURL: ""},
			wantErr: urlutil.ErrEmptyAthenzJwksURL,
		},
		{
			name: "no scheme",
			args: args{
				"dummy.com",
			},
			want:    &jwkd{athenzJwksURL: "https://dummy.com/oauth2/keys"},
			wantErr: nil,
		},
		{
			name: "http scheme",
			args: args{
				"http://dummy.com",
			},
			want:    &jwkd{athenzJwksURL: "https://dummy.com/oauth2/keys"},
			wantErr: nil,
		},
		{
			name: "https scheme",
			args: args{
				"https://dummy.com",
			},
			want:    &jwkd{athenzJwksURL: "https://dummy.com/oauth2/keys"},
			wantErr: nil,
		},
		{
			name: "unsupported scheme",
			args: args{
				"ftp://dummy.com",
			},
			want:    &jwkd{athenzJwksURL: ""},
			wantErr: urlutil.ErrUnsupportedScheme,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := &jwkd{}
			err := WithAthenzJwksURL(tt.args.url)(got)
			if err != tt.wantErr {
				t.Errorf("WithathenzJwksURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("WithathenzJwksURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWithRefreshPeriod(t *testing.T) {
	type args struct {
		t string
	}
	tests := []struct {
		name      string
		args      args
		checkFunc func(Option) error
	}{
		{
			name: "set success",
			args: args{
				"1h",
			},
			checkFunc: func(opt Option) error {
				pol := &jwkd{}
				if err := opt(pol); err != nil {
					return err
				}
				if pol.refreshPeriod != time.Hour {
					return fmt.Errorf("Error")
				}

				return nil
			},
		},
		{
			name: "invalid format",
			args: args{
				"dummy",
			},
			checkFunc: func(opt Option) error {
				pol := &jwkd{}
				if err := opt(pol); err == nil {
					return fmt.Errorf("expected error, but not return")
				}

				return nil
			},
		},
		{
			name: "empty value",
			args: args{
				"",
			},
			checkFunc: func(opt Option) error {
				pol := &jwkd{}
				if err := opt(pol); err != nil {
					return err
				}
				if !reflect.DeepEqual(pol, &jwkd{}) {
					return fmt.Errorf("expected no changes, but got %v", pol)
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithRefreshPeriod(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithRefreshPeriod() error = %v", err)
			}
		})
	}
}

func TestWithRetryDelay(t *testing.T) {
	type args struct {
		i string
	}
	tests := []struct {
		name      string
		args      args
		checkFunc func(Option) error
	}{
		{
			name: "set success",
			args: args{
				"1h",
			},
			checkFunc: func(opt Option) error {
				pol := &jwkd{}
				if err := opt(pol); err != nil {
					return err
				}
				if pol.retryDelay != time.Hour {
					return fmt.Errorf("Error")
				}

				return nil
			},
		},
		{
			name: "invalid format",
			args: args{
				"dummy",
			},
			checkFunc: func(opt Option) error {
				pol := &jwkd{}
				if err := opt(pol); err == nil {
					return fmt.Errorf("expected error, but not return")
				}

				return nil
			},
		},
		{
			name: "empty value",
			args: args{
				"",
			},
			checkFunc: func(opt Option) error {
				pol := &jwkd{}
				if err := opt(pol); err != nil {
					return err
				}
				if !reflect.DeepEqual(pol, &jwkd{}) {
					return fmt.Errorf("expected no changes, but got %v", pol)
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithRetryDelay(tt.args.i)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithRetryDelay() error= %v", err)
			}
		})
	}
}

func TestWithHTTPClient(t *testing.T) {
	type args struct {
		cl *http.Client
	}
	type test struct {
		name      string
		args      args
		checkFunc func(Option) error
	}
	tests := []test{
		func() test {
			cl := &http.Client{}
			return test{
				name: "set success",
				args: args{
					cl: cl,
				},
				checkFunc: func(opt Option) error {
					pol := &jwkd{}
					if err := opt(pol); err != nil {
						return err
					}
					if pol.client != cl {
						return fmt.Errorf("Error")
					}

					return nil
				},
			}
		}(),
		{
			name: "empty value",
			args: args{
				nil,
			},
			checkFunc: func(opt Option) error {
				pol := &jwkd{}
				if err := opt(pol); err != nil {
					return err
				}
				if !reflect.DeepEqual(pol, &jwkd{}) {
					return fmt.Errorf("expected no changes, but got %v", pol)
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithHTTPClient(tt.args.cl)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithHTTPClient() error = %v", err)
			}
		})
	}
}

func TestWithURLs(t *testing.T) {
	type args struct {
		urls []string
	}
	tests := []struct {
		name    string
		args    args
		want    *jwkd
		wantErr string
	}{
		{
			name: "empty string",
			args: args{
				urls: []string{""},
			},
			want:    &jwkd{urls: nil},
			wantErr: "parse \"\": empty url",
		},
		{
			name: "no scheme",
			args: args{
				urls: []string{"dummy.com"},
			},
			want:    &jwkd{urls: nil},
			wantErr: "parse \"dummy.com\": invalid URI for request",
		},
		{
			name: "http scheme",
			args: args{
				urls: []string{"http://dummy.com"},
			},
			want:    &jwkd{urls: []string{"http://dummy.com"}},
			wantErr: "",
		},
		{
			name: "https scheme",
			args: args{
				urls: []string{"https://dummy.com"},
			},
			want:    &jwkd{urls: []string{"https://dummy.com"}},
			wantErr: "",
		},
		{
			name: "http scheme with path",
			args: args{
				urls: []string{"http://dummy.com/path/to/resource"},
			},
			want:    &jwkd{urls: []string{"http://dummy.com/path/to/resource"}},
			wantErr: "",
		},
		{
			name: "https scheme with path",
			args: args{
				urls: []string{"https://dummy.com/path/to/resource"},
			},
			want:    &jwkd{urls: []string{"https://dummy.com/path/to/resource"}},
			wantErr: "",
		},
		{
			name: "unsupported scheme",
			args: args{
				urls: []string{"ftp://dummy.com"},
			},
			want:    &jwkd{},
			wantErr: urlutil.ErrUnsupportedScheme.Error(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := &jwkd{}
			err := WithURLs(tt.args.urls)(got)
			if err != nil {
				if err.Error() != tt.wantErr {
					t.Errorf("WithURLs() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("WithURLs() = %v, want %v", got, tt.want)
			}
		})
	}
}
