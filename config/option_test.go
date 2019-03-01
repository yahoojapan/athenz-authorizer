package config

import (
	"fmt"
	"testing"
	"time"
)

func TestAthenzURL(t *testing.T) {
	type args struct {
		athenzURL string
	}
	tests := []struct {
		name      string
		args      args
		checkFunc func(Option) error
	}{
		{
			name: "set athenz url success",
			args: args{
				athenzURL: "dummy",
			},
			checkFunc: func(got Option) error {
				c := &confd{}
				got(c)

				if c.athenzURL != "dummy" {
					return fmt.Errorf("cannot set athenz url")
				}
				return nil
			},
		},
		{
			name: "remove http:// prefix",
			args: args{
				athenzURL: "http://dummy",
			},
			checkFunc: func(got Option) error {
				c := &confd{}
				got(c)

				if c.athenzURL != "dummy" {
					return fmt.Errorf("cannot set athenz url")
				}
				return nil
			},
		},
		{
			name: "remove https:// prefix",
			args: args{
				athenzURL: "https://dummy",
			},
			checkFunc: func(got Option) error {
				c := &confd{}
				got(c)

				if c.athenzURL != "dummy" {
					return fmt.Errorf("cannot set athenz url")
				}
				return nil
			},
		},
		{
			name: "do not remove other protocol",
			args: args{
				athenzURL: "ftp://dummy",
			},
			checkFunc: func(got Option) error {
				c := &confd{}
				got(c)

				if c.athenzURL != "ftp://dummy" {
					return fmt.Errorf("cannot set athenz url")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AthenzURL(tt.args.athenzURL)
			if got == nil {
				t.Errorf("AthenzURL() = nil")
				return
			}
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("AthenzURL() = %v", err)
			}
		})
	}
}

func TestSysAuthDomain(t *testing.T) {
	type args struct {
		domain string
	}
	tests := []struct {
		name      string
		args      args
		checkFunc func(Option) error
	}{
		{
			name: "set sys.auth domain success",
			args: args{
				domain: "dummy",
			},
			checkFunc: func(got Option) error {
				c := &confd{}
				got(c)

				if c.sysAuthDomain != "dummy" {
					return fmt.Errorf("cannot set sys.auth domain")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SysAuthDomain(tt.args.domain)
			if got == nil {
				t.Errorf("SysAuthDomain() = nil")
				return
			}
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("SysAuthDomain() = %v", err)
			}
		})
	}
}

func TestETagExpTime(t *testing.T) {
	type args struct {
		time string
	}
	tests := []struct {
		name      string
		args      args
		checkFunc func(Option) error
	}{
		{
			name: "set etag expire time success",
			args: args{
				time: "2h",
			},
			checkFunc: func(got Option) error {
				c := &confd{}
				got(c)

				if c.etagExpTime != time.Duration(time.Hour*2) {
					return fmt.Errorf("cannot set etag expire time")
				}
				return nil
			},
		},
		{
			name: "cannot parse string to time.Duration",
			args: args{
				time: "dummy",
			},
			checkFunc: func(got Option) error {
				c := &confd{}
				err := got(c)

				if err == nil {
					return fmt.Errorf("invalid etag expire time was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ETagExpTime(tt.args.time)
			if got == nil {
				t.Errorf("ETagExpTime() = nil")
				return
			}
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("ETagExpTime() = %v", err)
			}
		})
	}
}

func TestETagFlushDur(t *testing.T) {
	type args struct {
		dur string
	}
	tests := []struct {
		name      string
		args      args
		checkFunc func(Option) error
	}{
		{
			name: "set etag expire time success",
			args: args{
				dur: "2h",
			},
			checkFunc: func(got Option) error {
				c := &confd{}
				got(c)

				if c.etagFlushDur != time.Duration(time.Hour*2) {
					return fmt.Errorf("cannot set etag flush duration")
				}
				return nil
			},
		},
		{
			name: "cannot parse string to time.Duration",
			args: args{
				dur: "dummy",
			},
			checkFunc: func(got Option) error {
				c := &confd{}
				err := got(c)

				if err == nil {
					return fmt.Errorf("invalid etag flush duration was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ETagFlushDur(tt.args.dur)
			if got == nil {
				t.Errorf("ETagFlushDur() = nil")
				return
			}
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("ETagFlushDur() = %v", err)
			}
		})
	}
}

func TestRefreshDuration(t *testing.T) {
	type args struct {
		dur string
	}
	tests := []struct {
		name      string
		args      args
		checkFunc func(Option) error
	}{
		{
			name: "set refresh duration success",
			args: args{
				dur: "2h",
			},
			checkFunc: func(got Option) error {
				c := &confd{}
				got(c)

				if c.refreshDuration != time.Duration(time.Hour*2) {
					return fmt.Errorf("cannot set refresh duration")
				}
				return nil
			},
		},
		{
			name: "cannot parse string to time.Duration",
			args: args{
				dur: "dummy",
			},
			checkFunc: func(got Option) error {
				c := &confd{}
				err := got(c)

				if err == nil {
					return fmt.Errorf("invalid refresh duration was set")
				}
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RefreshDuration(tt.args.dur)
			if got == nil {
				t.Errorf("RefreshDuration() = nil")
				return
			}
			if err := tt.checkFunc(got); err != nil {
				t.Errorf("RefreshDuration() = %v", err)
			}
		})
	}
}

//func TestHttpClient(t *testing.T) {
//	type args struct {
//		cli string
//	}
//	tests := []struct {
//		name      string
//		args      args
//		checkFunc func(Option) error
//	}{
//		{
//			name: "set http client success",
//			args: args{
//				cli: &http.Client{},
//			},
//			checkFunc: func(got Option) error {
//				c := &confd{}
//				got(c)
//
//				if c.client !=  {
//					return fmt.Errorf("cannot set http client")
//				}
//				return nil
//			},
//		},
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			got := HttpClient(tt.args.cli)
//			if got == nil {
//				t.Errorf("HttpClient() = nil")
//				return
//			}
//			if err := tt.checkFunc(got); err != nil {
//				t.Errorf("HttpClient() = %v", err)
//			}
//		})
//	}
//}
