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
package config

import (
	"net/http"
	"time"

	"github.com/pkg/errors"
)

var (
	defaultOptions = []Option{
		SysAuthDomain("sys.auth"),
		ETagExpTime("168h"), // 1 week
		ETagFlushDur("84h"),
		RefreshDuration("24h"),
		ErrRetryInterval("1m"),
		HTTPClient(&http.Client{}),
	}
)

// Option represents a functional options pattern interface
type Option func(*confd) error

// AthenzURL represents a AthenzURL functional option
func AthenzURL(url string) Option {
	return func(c *confd) error {
		if url == "" {
			return nil
		}
		c.athenzURL = regex.ReplaceAllString(url, "")
		return nil
	}
}

// SysAuthDomain represents a SysAuthDomain functional option
func SysAuthDomain(d string) Option {
	return func(c *confd) error {
		if d == "" {
			return nil
		}
		c.sysAuthDomain = d
		return nil
	}
}

// ETagExpTime represents a ETagExpTime functional option
func ETagExpTime(t string) Option {
	return func(c *confd) error {
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

// ETagFlushDur represents a ETagFlushDur functional option
func ETagFlushDur(t string) Option {
	return func(c *confd) error {
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

// RefreshDuration represents a RefreshDuration functional option
func RefreshDuration(t string) Option {
	return func(c *confd) error {
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

// HTTPClient represents a HTTPClient functional option
func HTTPClient(cl *http.Client) Option {
	return func(c *confd) error {
		if c != nil {
			c.client = cl
		}
		return nil
	}
}

// ErrRetryInterval represents a ErrRetryInterval functional option
func ErrRetryInterval(i string) Option {
	return func(c *confd) error {
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
