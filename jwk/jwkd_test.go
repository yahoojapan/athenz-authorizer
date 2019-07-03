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
	"context"
	"net/http"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	type args struct {
		opts []Option
	}
	tests := []struct {
		name    string
		args    args
		want    Daemon
		wantErr bool
	}{
		{
			name: "New daemon success",
			args: args{
				opts: []Option{
					WithAthenzURL("www.dummy.com"),
				},
			},
			want: &jwkd{
				athenzURL:        "www.dummy.com",
				refreshDuration:  time.Hour * 24,
				errRetryInterval: time.Millisecond,
				client:           http.DefaultClient,
			},
		},
		{
			name: "New daemon fail",
			args: args{
				opts: []Option{
					WithRefreshDuration("dummy"),
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.args.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_jwkd_Start(t *testing.T) {
	type fields struct {
		athenzURL        string
		refreshDuration  time.Duration
		errRetryInterval time.Duration
		client           *http.Client
		keys             atomic.Value
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   <-chan error
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := &jwkd{
				athenzURL:        tt.fields.athenzURL,
				refreshDuration:  tt.fields.refreshDuration,
				errRetryInterval: tt.fields.errRetryInterval,
				client:           tt.fields.client,
				keys:             tt.fields.keys,
			}
			if got := j.Start(tt.args.ctx); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("jwkd.Start() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_jwkd_Update(t *testing.T) {
	type fields struct {
		athenzURL        string
		refreshDuration  time.Duration
		errRetryInterval time.Duration
		client           *http.Client
		keys             atomic.Value
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := &jwkd{
				athenzURL:        tt.fields.athenzURL,
				refreshDuration:  tt.fields.refreshDuration,
				errRetryInterval: tt.fields.errRetryInterval,
				client:           tt.fields.client,
				keys:             tt.fields.keys,
			}
			if err := j.Update(tt.args.ctx); (err != nil) != tt.wantErr {
				t.Errorf("jwkd.Update() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_jwkd_GetProvider(t *testing.T) {
	type fields struct {
		athenzURL        string
		refreshDuration  time.Duration
		errRetryInterval time.Duration
		client           *http.Client
		keys             atomic.Value
	}
	tests := []struct {
		name   string
		fields fields
		want   Provider
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := &jwkd{
				athenzURL:        tt.fields.athenzURL,
				refreshDuration:  tt.fields.refreshDuration,
				errRetryInterval: tt.fields.errRetryInterval,
				client:           tt.fields.client,
				keys:             tt.fields.keys,
			}
			if got := j.GetProvider(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("jwkd.GetProvider() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_jwkd_getKey(t *testing.T) {
	type fields struct {
		athenzURL        string
		refreshDuration  time.Duration
		errRetryInterval time.Duration
		client           *http.Client
		keys             atomic.Value
	}
	type args struct {
		keyID string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   interface{}
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := &jwkd{
				athenzURL:        tt.fields.athenzURL,
				refreshDuration:  tt.fields.refreshDuration,
				errRetryInterval: tt.fields.errRetryInterval,
				client:           tt.fields.client,
				keys:             tt.fields.keys,
			}
			if got := j.getKey(tt.args.keyID); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("jwkd.getKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
