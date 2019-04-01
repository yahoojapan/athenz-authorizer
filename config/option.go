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

type Option func(*confd) error

func AthenzURL(url string) Option {
	return func(c *confd) error {
		if url == "" {
			return nil
		}
		c.athenzURL = regex.ReplaceAllString(url, "")
		return nil
	}
}

func SysAuthDomain(d string) Option {
	return func(c *confd) error {
		if d == "" {
			return nil
		}
		c.sysAuthDomain = d
		return nil
	}
}

func ETagExpTime(t string) Option {
	return func(c *confd) error {
		if t == "" {
			return nil
		}
		if etagExpTime, err := time.ParseDuration(t); err != nil {
			return errors.Wrap(err, "invalid etag expire time")
		} else {
			c.etagExpTime = etagExpTime
			return nil
		}
	}
}

func ETagFlushDur(t string) Option {
	return func(c *confd) error {
		if t == "" {
			return nil
		}
		if etagFlushDur, err := time.ParseDuration(t); err != nil {
			return errors.Wrap(err, "invalid etag flush duration")
		} else {
			c.etagFlushDur = etagFlushDur
			return nil
		}
	}
}

func RefreshDuration(t string) Option {
	return func(c *confd) error {
		if t == "" {
			return nil
		}
		if rd, err := time.ParseDuration(t); err != nil {
			return errors.Wrap(err, "invalid refresh druation")
		} else {
			c.refreshDuration = rd
			return nil
		}
	}
}

func HTTPClient(cl *http.Client) Option {
	return func(c *confd) error {
		if c != nil {
			c.client = cl
		}
		return nil
	}
}

func ErrRetryInterval(i string) Option {
	return func(c *confd) error {
		if i == "" {
			return nil
		}
		if ri, err := time.ParseDuration(i); err != nil {
			return errors.Wrap(err, "invalid err retry interval")
		} else {
			c.errRetryInterval = ri
			return nil
		}
	}
}
