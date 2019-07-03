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
	"reflect"
	"testing"

	"github.com/yahoojapan/athenz-authorizer/jwk"
	"github.com/yahoojapan/athenz-authorizer/pubkey"
)

func TestWithPubkeyProvider(t *testing.T) {
	type args struct {
		pkp pubkey.Provider
	}
	tests := []struct {
		name string
		args args
		want Option
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := WithPubkeyProvider(tt.args.pkp); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("WithPubkeyProvider() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWithJWKProvider(t *testing.T) {
	type args struct {
		jwkp jwk.Provider
	}
	tests := []struct {
		name string
		args args
		want Option
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := WithJWKProvider(tt.args.jwkp); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("WithJWKProvider() = %v, want %v", got, tt.want)
			}
		})
	}
}
