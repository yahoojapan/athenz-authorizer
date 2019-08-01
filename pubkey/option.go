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
package pubkey

import (
	"net/http"
	"time"

	"github.com/pkg/errors"
	urlutil "github.com/yahoojapan/athenz-authorizer/internal/url"
)

var (
	defaultOptions = []Option{
		WithSysAuthDomain("sys.auth"),
		WithEtagExpTime("168h"), // 1 week
		WithEtagFlushDuration("84h"),
		WithRefreshDuration("24h"),
		WithErrRetryInterval("1m"),
		WithHTTPClient(&http.Client{}),
	}
)

// Option represents a functional option
type Option func(*pubkeyd) error

// WithAthenzURL returns an AthenzURL functional option
func WithAthenzURL(url string) Option {
	return func(p *pubkeyd) error {
		u := urlutil.TrimHTTPScheme(url)
		if urlutil.HasScheme(u) {
			return urlutil.ErrUnsupportedScheme
		}
		p.athenzURL = u
		return nil
	}
}

// WithSysAuthDomain returns a SysAuthDomain functional option
func WithSysAuthDomain(d string) Option {
	return func(p *pubkeyd) error {
		if d == "" {
			return nil
		}
		p.sysAuthDomain = d
		return nil
	}
}

// WithEtagExpTime returns an EtagExpTime functional option
func WithEtagExpTime(t string) Option {
	return func(p *pubkeyd) error {
		if t == "" {
			return nil
		}

		etagExpTime, err := time.ParseDuration(t)
		if err != nil {
			return errors.Wrap(err, "invalid etag expire time")
		}
		p.etagExpTime = etagExpTime
		return nil
	}
}

// WithEtagFlushDuration returns an EtagFlushDur functional option
func WithEtagFlushDuration(t string) Option {
	return func(p *pubkeyd) error {
		if t == "" {
			return nil
		}

		etagFlushDur, err := time.ParseDuration(t)
		if err != nil {
			return errors.Wrap(err, "invalid etag flush duration")
		}
		p.etagFlushDur = etagFlushDur
		return nil
	}
}

// WithRefreshDuration returns a RefreshDuration functional option
func WithRefreshDuration(t string) Option {
	return func(p *pubkeyd) error {
		if t == "" {
			return nil
		}

		rd, err := time.ParseDuration(t)
		if err != nil {
			return errors.Wrap(err, "invalid refresh duration")
		}
		p.refreshDuration = rd
		return nil
	}
}

// WithHTTPClient returns a HTTPClient functional option
func WithHTTPClient(cl *http.Client) Option {
	return func(p *pubkeyd) error {
		if p != nil {
			p.client = cl
		}
		return nil
	}
}

// WithErrRetryInterval returns an ErrRetryInterval functional option
func WithErrRetryInterval(i string) Option {
	return func(p *pubkeyd) error {
		if i == "" {
			return nil
		}

		ri, err := time.ParseDuration(i)
		if err != nil {
			return errors.Wrap(err, "invalid err retry interval")
		}
		p.errRetryInterval = ri
		return nil
	}
}
