package policy

import (
	"testing"
)

func TestNewPolicyd(t *testing.T) {
	type args struct {
		opts []Option
	}
	tests := []struct {
		name      string
		args      args
		want      Policyd
		checkFunc func(got Policyd) error
		wantErr   bool
	}{
		/*
			{
				name: "new success",
				args: args{
					opts: []Option{},
				},
				checkFunc: func(got Policyd) error {
					p := got.(*policy)

					return fmt.Errorf("%v", p)
				},
			},
		*/
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewPolicyd(tt.args.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewPolicyd() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err := tt.checkFunc(got); err != nil {
				t.Errorf("NewPolicyd() = %v", err)
			}
		})
	}
}
