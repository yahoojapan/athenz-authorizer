package config

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"testing"
	"time"

	ntokend "github.com/yahoojapan/athenz-ntokend"
	"github.com/kpango/gache"
)

func TestNewAthenzConfd(t *testing.T) {
	type args struct {
		host string
		key  string
		c    gache.Gache
	}
	type test struct {
		name string
		args args
		want AthenzConfd
	}
	tests := []test{
		func() test {
			ga := gache.New().StartExpired(context.Background(), time.Second)
			return test{
				name: "",
				args: args{
					host: "test.domain.com",
					key:  "aaa",
					c:    ga,
				},
				want: &confd{
					sysAuthDomain: "sys.auth",
					etagExpTime:   12 * time.Hour,
					etagCache:     ga,
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewAthenzConfd(tt.args.host, tt.args.key, tt.args.c); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewAthenzConfd() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_confd_FetchAthenzConfig(t *testing.T) {
	type fields struct {
		athenzHost    string
		sysAuthDomain string
		authHeaderKey string
		ntoken        ntokend.TokenProvider
		client        *http.Client
		etagCache     gache.Gache
		etagExpTime   time.Duration
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *AthenzConfig
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &confd{
				athenzHost:    tt.fields.athenzHost,
				sysAuthDomain: tt.fields.sysAuthDomain,
				authHeaderKey: tt.fields.authHeaderKey,
				ntoken:        tt.fields.ntoken,
				client:        tt.fields.client,
				etagCache:     tt.fields.etagCache,
				etagExpTime:   tt.fields.etagExpTime,
			}
			got, err := c.FetchAthenzConfig(tt.args.ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("confd.FetchAthenzConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("confd.FetchAthenzConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_confd_fetchPubKeyEntries(t *testing.T) {
	type fields struct {
		athenzHost    string
		sysAuthDomain string
		authHeaderKey string
		ntoken        ntokend.TokenProvider
		client        *http.Client
		etagCache     gache.Gache
		etagExpTime   time.Duration
	}
	type args struct {
		ctx context.Context
		env athenzEnv
	}
	type test struct {
		name      string
		fields    fields
		args      args
		want      *sysAuthConfig
		afterFunc func()
		wantErr   bool
	}
	regex = regexp.MustCompile("^(http|https)://")
	tests := []test{
		func() test {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(`{"name":"yby.wdiu.travel.travel-site","publicKeys":[{"key":"testkey","id":"0"}],"modified":"2018-05-07T06:29:11.163Z"}%`))
				w.WriteHeader(200)
			})
			srv := httptest.NewTLSServer(handler)

			return test{
				name: "get pub key entries successful",
				fields: fields{
					athenzHost:    regex.ReplaceAllString(srv.URL, ""),
					sysAuthDomain: "auth.domain",
					authHeaderKey: "",
					ntoken: func() (string, error) {
						return "", nil
					},
					client:      srv.Client(),
					etagCache:   gache.New().StartExpired(context.Background(), time.Second),
					etagExpTime: time.Second,
				},
				args: args{
					ctx: context.Background(),
					env: "travel-site",
				},
				want: &sysAuthConfig{
					Modified: "2018-05-07T06:29:11.163Z",
					Name:     "yby.wdiu.travel.travel-site",
					PublicKeys: []publicKey{
						{
							ID:  "0",
							Key: "testkey",
						},
					},
				},
				afterFunc: func() {
					srv.Close()
				},
				wantErr: false,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.afterFunc != nil {
				defer tt.afterFunc()
			}

			c := &confd{
				athenzHost:    tt.fields.athenzHost,
				sysAuthDomain: tt.fields.sysAuthDomain,
				authHeaderKey: tt.fields.authHeaderKey,
				ntoken:        tt.fields.ntoken,
				client:        tt.fields.client,
				etagCache:     tt.fields.etagCache,
				etagExpTime:   tt.fields.etagExpTime,
			}
			got, err := c.fetchPubKeyEntries(tt.args.ctx, tt.args.env)
			if (err != nil) != tt.wantErr {
				t.Errorf("confd.fetchPubKeyEntries() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("confd.fetchPubKeyEntries() = %v, want %v", got, tt.want)
			}
		})
	}
}
