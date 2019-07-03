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

// Option represents a functional options pattern interface
type Option func(*pubkeyd) error

// WithAthenzURL represents a AthenzURL functional option
func WithAthenzURL(url string) Option {
	return func(c *pubkeyd) error {
		if url == "" {
			return nil
		}
		c.athenzURL = regex.ReplaceAllString(url, "")
		return nil
	}
}

// WithSysAuthDomain represents a SysAuthDomain functional option
func WithSysAuthDomain(d string) Option {
	return func(c *pubkeyd) error {
		if d == "" {
			return nil
		}
		c.sysAuthDomain = d
		return nil
	}
}

// WithEtagExpTime represents a EtagExpTime functional option
func WithEtagExpTime(t string) Option {
	return func(c *pubkeyd) error {
		if t == "" {
			return nil
		}

		etagExpTime, err := time.ParseDuration(t)
		if err != nil {
			return errors.Wrap(err, "invalid etag expire time")
		}
		c.etagExpTime = etagExpTime
		return nil
	}
}

// WithEtagFlushDuration represents a EtagFlushDur functional option
func WithEtagFlushDuration(t string) Option {
	return func(c *pubkeyd) error {
		if t == "" {
			return nil
		}

		etagFlushDur, err := time.ParseDuration(t)
		if err != nil {
			return errors.Wrap(err, "invalid etag flush duration")
		}
		c.etagFlushDur = etagFlushDur
		return nil
	}
}

// WithRefreshDuration represents a RefreshDuration functional option
func WithRefreshDuration(t string) Option {
	return func(c *pubkeyd) error {
		if t == "" {
			return nil
		}

		rd, err := time.ParseDuration(t)
		if err != nil {
			return errors.Wrap(err, "invalid refresh druation")
		}
		c.refreshDuration = rd
		return nil
	}
}

// WithHTTPClient represents a HTTPClient functional option
func WithHTTPClient(cl *http.Client) Option {
	return func(c *pubkeyd) error {
		if c != nil {
			c.client = cl
		}
		return nil
	}
}

// WithErrRetryInterval represents a ErrRetryInterval functional option
func WithErrRetryInterval(i string) Option {
	return func(c *pubkeyd) error {
		if i == "" {
			return nil
		}

		ri, err := time.ParseDuration(i)
		if err != nil {
			return errors.Wrap(err, "invalid err retry interval")
		}
		c.errRetryInterval = ri
		return nil
	}
}
