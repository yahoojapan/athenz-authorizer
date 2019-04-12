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
package policy

import (
	"net/http"
	"time"

	"github.com/pkg/errors"
	"github.com/yahoojapan/athenz-policy-updater/pubkey"
)

var (
	defaultOptions = []Option{
		ExpireMargin("3h"),
		EtagFlushDur("12h"),
		EtagExpTime("24h"),
		RefreshDuration("30m"),
		ErrRetryInterval("1m"),
		HTTPClient(&http.Client{}),
	}
)

// Option represents a functional options pattern interface
type Option func(*policyd) error

// EtagFlushDur represents a ETagFlushDur functional option
func EtagFlushDur(t string) Option {
	return func(pol *policyd) error {
		if t == "" {
			return nil
		}
		etagFlushDur, err := time.ParseDuration(t)
		if err != nil {
			return errors.Wrap(err, "invalid flush duration")
		}
		pol.etagFlushDur = etagFlushDur
		return nil
	}
}

// ExpireMargin represents a ExpiryMargin functional option
func ExpireMargin(t string) Option {
	return func(pol *policyd) error {
		if t == "" {
			return nil
		}
		expireMargin, err := time.ParseDuration(t)
		if err != nil {
			return errors.Wrap(err, "invalid expire margin")
		}
		pol.expireMargin = expireMargin
		return nil
	}
}

// EtagExpTime represents a EtagExpTime functional option
func EtagExpTime(t string) Option {
	return func(pol *policyd) error {
		if t == "" {
			return nil
		}
		etagExpTime, err := time.ParseDuration(t)
		if err != nil {
			return errors.Wrap(err, "invalid etag expire time")
		}
		pol.etagExpTime = etagExpTime
		return nil
	}
}

// AthenzURL represents a AthenzURL functional option
func AthenzURL(url string) Option {
	return func(pol *policyd) error {
		if url == "" {
			return nil
		}
		pol.athenzURL = url
		return nil
	}
}

// AthenzDomains represents a AthenzDomain functional option
func AthenzDomains(doms ...string) Option {
	return func(pol *policyd) error {
		if doms == nil {
			return nil
		}
		pol.athenzDomains = doms
		return nil
	}
}

// RefreshDuration represents a RefreshDuration functional option
func RefreshDuration(t string) Option {
	return func(pol *policyd) error {
		if t == "" {
			return nil
		}
		rd, err := time.ParseDuration(t)
		if err != nil {
			return errors.Wrap(err, "invalid refresh duration")
		}
		pol.refreshDuration = rd
		return nil
	}
}

// HTTPClient represents a HttpClient functional option
func HTTPClient(c *http.Client) Option {
	return func(pol *policyd) error {
		if c != nil {
			pol.client = c
		}
		return nil
	}
}

// PubKeyProvider represents a PubKeyProvider functional option
func PubKeyProvider(pkp pubkey.Provider) Option {
	return func(pol *policyd) error {
		if pkp != nil {
			pol.pkp = pkp
		}
		return nil
	}
}

// ErrRetryInterval represents a ErrRetryInterval functional option
func ErrRetryInterval(i string) Option {
	return func(pol *policyd) error {
		if i == "" {
			return nil
		}
		ri, err := time.ParseDuration(i)
		if err != nil {
			return errors.Wrap(err, "invalid err retry interval")
		}
		pol.errRetryInterval = ri
		return nil
	}
}
