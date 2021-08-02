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
	"testing"

	authcore "github.com/AthenZ/athenz/libs/go/zmssvctoken"
	"github.com/yahoojapan/athenz-authorizer/v5/pubkey"
)

func TestWithPubkeyProvider(t *testing.T) {
	type args struct {
		pkp pubkey.Provider
	}
	type test struct {
		name      string
		args      args
		checkFunc func(Option) error
	}
	tests := []test{
		func() test {
			pkp := pubkey.Provider(func(pubkey.AthenzEnv, string) authcore.Verifier {
				return nil
			})
			return test{
				name: "set success",
				args: args{
					pkp: pkp,
				},
				checkFunc: func(opt Option) error {
					pol := &rtp{}
					if err := opt(pol); err != nil {
						return err
					}
					if reflect.ValueOf(pol.pkp) != reflect.ValueOf(pkp) {
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
				pol := &rtp{}
				if err := opt(pol); err != nil {
					return err
				}
				if !reflect.DeepEqual(pol, &rtp{}) {
					return fmt.Errorf("expected no changes, but got %v", pol)
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithPubkeyProvider(tt.args.pkp)
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("WithPubkeyProvider() error: %v", err)
			}
		})
	}
}
