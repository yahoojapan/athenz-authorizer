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
	urlutil "github.com/yahoojapan/athenz-authorizer/v4/internal/url"
	"github.com/yahoojapan/athenz-authorizer/v4/pubkey"
)

var (
	defaultOptions = []Option{
		WithExpiryMargin("3h"),
		WithRefreshPeriod("30m"),
		WithPurgePeriod("1h"),
		WithRetryDelay("1m"),
		WithRetryAttempts(2),
		WithHTTPClient(http.DefaultClient),
	}
)

// Option represents a functional option
type Option func(*policyd) error

// WithPubKeyProvider returns a PubKeyProvider functional option
func WithPubKeyProvider(pkp pubkey.Provider) Option {
	return func(pol *policyd) error {
		if pkp != nil {
			pol.pkp = pkp
		}
		return nil
	}
}

// WithAthenzURL returns an AthenzURL functional option
func WithAthenzURL(url string) Option {
	return func(pol *policyd) error {
		u := urlutil.TrimHTTPScheme(url)
		if urlutil.HasScheme(u) {
			return urlutil.ErrUnsupportedScheme
		}
		pol.athenzURL = u
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

// WithExpiryMargin returns an ExpiryMargin functional option
func WithExpiryMargin(d string) Option {
	return func(pol *policyd) error {
		if d == "" {
			return nil
		}
		em, err := time.ParseDuration(d)
		if err != nil {
			return errors.Wrap(err, "invalid expiry margin")
		}
		pol.expiryMargin = em
		return nil
	}
}

// WithRefreshPeriod returns a RefreshPeriod functional option
func WithRefreshPeriod(d string) Option {
	return func(pol *policyd) error {
		if d == "" {
			return nil
		}
		rp, err := time.ParseDuration(d)
		if err != nil {
			return errors.Wrap(err, "invalid refresh period")
		}
		pol.refreshPeriod = rp
		return nil
	}
}

// WithPurgePeriod returns a PurgePeriod functional option
func WithPurgePeriod(d string) Option {
	return func(pol *policyd) error {
		if d == "" {
			return nil
		}
		pp, err := time.ParseDuration(d)
		if err != nil {
			return errors.Wrap(err, "invalid purge period")
		}
		pol.purgePeriod = pp
		return nil
	}
}

// WithRetryDelay returns an RetryDelay functional option
func WithRetryDelay(d string) Option {
	return func(pol *policyd) error {
		if d == "" {
			return nil
		}
		rd, err := time.ParseDuration(d)
		if err != nil {
			return errors.Wrap(err, "invalid retry delay")
		}
		pol.retryDelay = rd
		return nil
	}
}

// WithRetryAttempts returns an RetryAttempts functional option
func WithRetryAttempts(c int) Option {
	return func(pol *policyd) error {
		if c == 0 {
			return nil
		}
		pol.retryAttempts = c
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
