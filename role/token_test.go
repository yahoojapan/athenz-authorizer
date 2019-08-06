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
	"strconv"
	"testing"
	"time"

	"github.com/kpango/fastime"
)

func TestToken_SetParams(t *testing.T) {
	type fields struct {
		Domain        string
		Roles         []string
		ExpiryTime    time.Time
		KeyID         string
		Signature     string
		UnsignedToken string
	}
	type args struct {
		key   string
		value string
	}
	tests := []struct {
		name      string
		fields    fields
		args      args
		checkFunc func(got *Token) error
		wantErr   bool
	}{
		{
			name:   "set param d success",
			fields: fields{},
			args: args{
				key:   "d",
				value: "dummyd",
			},
			checkFunc: func(got *Token) error {
				expected := &Token{
					Domain: "dummyd",
				}

				if !reflect.DeepEqual(got, expected) {
					return fmt.Errorf("erorr")
				}

				return nil
			},
		},
		{
			name:   "set param e success",
			fields: fields{},
			args: args{
				key:   "e",
				value: "1550643321",
			},
			checkFunc: func(got *Token) error {
				expected := &Token{
					ExpiryTime: func() time.Time {
						t, _ := strconv.ParseInt("1550643321", 10, 64)
						return time.Unix(t, 0)
					}(),
				}

				if !reflect.DeepEqual(got, expected) {
					return fmt.Errorf("erorr")
				}

				return nil
			},
		},
		{
			name:   "set param e correct",
			fields: fields{},
			args: args{
				key:   "e",
				value: "1550643321",
			},
			checkFunc: func(got *Token) error {
				// 2019-02-20 06:15:21 +0000 UTC
				expected := time.Date(2019, 2, 20, 6, 15, 21, 0, time.UTC)
				if !expected.Equal(got.ExpiryTime) {
					return fmt.Errorf("got: %v, expected: %v", got.ExpiryTime, expected)
				}

				return nil
			},
		},
		{
			name:   "set param e fail",
			fields: fields{},
			args: args{
				key:   "e",
				value: "abcde",
			},
			wantErr: true,
		},
		{
			name:   "set param k success",
			fields: fields{},
			args: args{
				key:   "k",
				value: "dummyk",
			},
			checkFunc: func(got *Token) error {
				expected := &Token{
					KeyID: "dummyk",
				}

				if !reflect.DeepEqual(got, expected) {
					return fmt.Errorf("erorr")
				}

				return nil
			},
		},
		{
			name:   "set param r success",
			fields: fields{},
			args: args{
				key:   "r",
				value: "r1,r2",
			},
			checkFunc: func(got *Token) error {
				expected := &Token{
					Roles: []string{"r1", "r2"},
				}

				if !reflect.DeepEqual(got, expected) {
					return fmt.Errorf("erorr")
				}

				return nil
			},
		},
		{
			name:   "set param s success",
			fields: fields{},
			args: args{
				key:   "s",
				value: "dummys",
			},
			checkFunc: func(got *Token) error {
				expected := &Token{
					Signature: "dummys",
				}

				if !reflect.DeepEqual(got, expected) {
					return fmt.Errorf("erorr")
				}

				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Token{
				Domain:        tt.fields.Domain,
				Roles:         tt.fields.Roles,
				ExpiryTime:    tt.fields.ExpiryTime,
				KeyID:         tt.fields.KeyID,
				Signature:     tt.fields.Signature,
				UnsignedToken: tt.fields.UnsignedToken,
			}
			if err := r.SetParams(tt.args.key, tt.args.value); (err != nil) != tt.wantErr {
				t.Errorf("Token.SetParams() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.checkFunc != nil {
				if err := tt.checkFunc(r); err != nil {
					t.Errorf("Token set not expected, err: %v", err)
				}
			}
		})
	}
}

func TestToken_Expired(t *testing.T) {
	type fields struct {
		Domain        string
		Roles         []string
		ExpiryTime    time.Time
		KeyID         string
		Signature     string
		UnsignedToken string
	}
	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{
			name: "expired",
			fields: fields{
				ExpiryTime: fastime.Now().Add(-1 * time.Hour),
			},
			want: true,
		},
		{
			name: "not expired",
			fields: fields{
				ExpiryTime: fastime.Now().Add(time.Hour),
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Token{
				Domain:        tt.fields.Domain,
				Roles:         tt.fields.Roles,
				ExpiryTime:    tt.fields.ExpiryTime,
				KeyID:         tt.fields.KeyID,
				Signature:     tt.fields.Signature,
				UnsignedToken: tt.fields.UnsignedToken,
			}
			if got := r.Expired(); got != tt.want {
				t.Errorf("Token.Expired() = %v, want %v", got, tt.want)
			}
		})
	}
}
