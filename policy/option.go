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
	"github.com/yahoojapan/athenz-authorizer/pubkey"
)

var (
	defaultOptions = []Option{
		WithExpireMargin("3h"),
		WithEtagFlushDuration("12h"),
		WithEtagExpTime("24h"),
		WithPolicyExpiredDuration("1m"),
		WithRefreshDuration("30m"),
		WithErrRetryInterval("1m"),
		WithHTTPClient(http.DefaultClient),
	}
)

// Option represents a functional option
type Option func(*policyd) error

// WithEtagFlushDuration returns an ETagFlushDur functional option
func WithEtagFlushDuration(t string) Option {
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

// WithExpireMargin returns an ExpiryMargin functional option
func WithExpireMargin(t string) Option {
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

// WithEtagExpTime returns an EtagExpTime functional option
func WithEtagExpTime(t string) Option {
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

// WithAthenzURL returns an AthenzURL functional option
func WithAthenzURL(url string) Option {
	return func(pol *policyd) error {
		if url == "" {
			return nil
		}
		pol.athenzURL = url
		return nil
	}
}

// WithAthenzDomains represents an AthenzDomain functional option
func WithAthenzDomains(doms ...string) Option {
	return func(pol *policyd) error {
		if doms == nil {
			return nil
		}
		pol.athenzDomains = doms
		return nil
	}
}

// WithPolicyExpiredDuration returns a PolicyExpiredDuration functional option
func WithPolicyExpiredDuration(t string) Option {
	return func(pol *policyd) error {
		if t == "" {
			return nil
		}
		rd, err := time.ParseDuration(t)
		if err != nil {
			return errors.Wrap(err, "invalid refresh duration")
		}
		pol.policyExpiredDuration = rd
		return nil
	}
}

// WithRefreshDuration returns a RefreshDuration functional option
func WithRefreshDuration(t string) Option {
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

// WithHTTPClient returns a HttpClient functional option
func WithHTTPClient(c *http.Client) Option {
	return func(pol *policyd) error {
		if c != nil {
			pol.client = c
		}
		return nil
	}
}

// WithPubKeyProvider returns a PubKeyProvider functional option
func WithPubKeyProvider(pkp pubkey.Provider) Option {
	return func(pol *policyd) error {
		if pkp != nil {
			pol.pkp = pkp
		}
		return nil
	}
}

// WithErrRetryInterval returns an ErrRetryInterval functional option
func WithErrRetryInterval(i string) Option {
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
