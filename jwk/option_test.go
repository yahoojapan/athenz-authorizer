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
)

func TestWithAthenzURL(t *testing.T) {
	type args struct {
		url string
	}
	tests := []struct {
		name      string
		args      args
		checkFunc func(Option) error
	}{
		{
			name: "set success",
			args: args{
				"http://dummy.com",
			},
			checkFunc: func(opt Option) error {
				pol := &jwkd{}
				if err := opt(pol); err != nil {
					return err
				}
				if pol.athenzURL != "http://dummy.com" {
					return fmt.Errorf("Error")
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
			got := WithAthenzURL(tt.args.url)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithAthenzURL() error = %v", err)
			}
		})
	}
}

func TestWithRefreshDuration(t *testing.T) {
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
				if pol.refreshDuration != time.Hour {
					return fmt.Errorf("Error")
				}

				return nil
			},
		}, {
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
			got := WithRefreshDuration(tt.args.t)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithRefreshDuration() error = %v", err)
			}
		})
	}
}

func TestWithErrRetryInterval(t *testing.T) {
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
				if pol.errRetryInterval != time.Hour {
					return fmt.Errorf("Error")
				}

				return nil
			},
		}, {
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
			got := WithErrRetryInterval(tt.args.i)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithErrRetryInterval() error= %v", err)
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
