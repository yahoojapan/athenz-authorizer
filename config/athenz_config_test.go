package config

import (
	"fmt"
	//	"context"
	//	"net/http"
	//	"net/http/httptest"
	//	"reflect"
	//	"regexp"
	"testing"
	"sync"
	//	"time"
	//	ntokend "github.com/yahoojapan/athenz-ntokend"
)

func TestNewAthenzConfd(t *testing.T) {
	type args struct {
		opts []Option
	}
	type test struct {
		name      string
		args      args
		checkFunc func(AthenzConfd) error
	}
	tests := []test{
		test{
			name: "new athenz confd success",
			args: args{
				opts: []Option{},
			},
			checkFunc: func(got AthenzConfd) error {
				if got.(*confd).sysAuthDomain != "sys.auth" {
					return fmt.Errorf("cannot set default options")
				}
				return nil
			},
		},
		{
			name: "new athenz confd success with options",
			args: args{
				opts: []Option{
					SysAuthDomain("dummyd"),
					AthenzURL("dummyURL"),
				},
			},
			checkFunc: func(got AthenzConfd) error {
				if got.(*confd).sysAuthDomain != "dummyd" || got.(*confd).athenzURL != "dummyURL" {
					return fmt.Errorf("cannot set optional params")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewAthenzConfd(tt.args.opts...)
			if err != nil {
				t.Errorf("NewAthenzConfd() =  %v", err)
			}
			err = tt.checkFunc(got)
			if err != nil {
				t.Errorf("NewAthenzConfd() = %v", err)
			}
		})
	}
}

func Test_GetPubKey(t *testing.T) {
	c := &confd{
		confCache: &AthenzConfig{
			ZMSPubKeys: new(sync.Map),
			ZTSPubKeys: new(sync.Map),
		},
	}
	type args struct {
		env AthenzEnv
		keyID string
	}
	type test struct {
		name string
		args args
		want *VerifierMock
	}
	tests := []test{
		func() test {
			zmsVer := &VerifierMock{}
			ztsVer := &VerifierMock{}
			c.confCache.ZMSPubKeys.Store("0", zmsVer)
			c.confCache.ZTSPubKeys.Store("0", ztsVer)
			return test{
				name: "success",
				args: args{
					env: "zms",
					keyID: "0",
				},
				want: zmsVer,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := c.getPubKey(tt.args.env, tt.args.keyID)
			if got != tt.want {
				t.Errorf("getPubKey() = expect: %v	result: %v", tt.want, got)
			}
		})
	}
}
