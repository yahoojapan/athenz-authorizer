package policy

import (
	"fmt"
	"reflect"
	"regexp"
	"testing"

	"github.com/pkg/errors"
)

func TestNewAssertion(t *testing.T) {
	type args struct {
		action   string
		resource string
		effect   string
	}
	tests := []struct {
		name      string
		args      args
		want      *Assertion
		checkFunc func(got, want *Assertion) error
		wantErr   error
	}{
		{
			name: "return effect success",
			args: args{
				resource: "dom:res",
				action:   "act",
				effect:   "allow",
			},
			want: &Assertion{
				ResourceDomain: "dom",
				Reg: func() *regexp.Regexp {
					r, _ := regexp.Compile("^act-res$")
					return r
				}(),
				Effect: nil,
			},
			checkFunc: func(got, want *Assertion) error {
				if !reflect.DeepEqual(got, want) {
					return fmt.Errorf("got: %v, want: %v", got, want)
				}

				return nil
			},
		},
		{
			name: "return effect fail",
			args: args{
				resource: "dom:res",
				action:   "act",
				effect:   "deny",
			},
			want: &Assertion{
				ResourceDomain: "dom",
				Reg: func() *regexp.Regexp {
					r, _ := regexp.Compile("^act-res$")
					return r
				}(),
				Effect: errors.New("policy deny: Access Check was explicitly denied"),
			},
			checkFunc: func(got, want *Assertion) error {
				if got.ResourceDomain != want.ResourceDomain ||
					!reflect.DeepEqual(got.Reg, want.Reg) ||
					got.Effect.Error() != want.Effect.Error() {
					return fmt.Errorf("got: %v, want: %v", got, want)
				}

				return nil
			},
		},
		{
			name: "resource domain not valid",
			args: args{
				resource: "domres",
				action:   "act",
				effect:   "deny",
			},
			wantErr: errors.New("assestion format not correct: Access denied due to invalie/empty policy resources"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewAssertion(tt.args.action, tt.args.resource, tt.args.effect)
			if tt.checkFunc != nil {
				if err := tt.checkFunc(got, tt.want); err != nil {
					t.Errorf("NewAssertion error: %v", err)
				}
			}
			if err == nil {
				if tt.wantErr != nil {
					t.Errorf("NewAssertion = %v, wantErr %v", err, tt.wantErr)
				}
			} else {
				if tt.wantErr == nil {
					t.Errorf("NewAssertion error = %v, wantErr %v", err, tt.wantErr)
				} else if err.Error() != tt.wantErr.Error() {
					t.Errorf("NewAssertio error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}
