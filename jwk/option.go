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

package jwk

import (
	"net/http"
	"time"

	"github.com/pkg/errors"
	urlutil "github.com/yahoojapan/athenz-authorizer/v4/internal/url"
)

var (
	defaultOptions = []Option{
		WithRefreshPeriod("24h"),
		WithRetryDelay("1m"),
		WithHTTPClient(http.DefaultClient),
	}
)

// Option represents a functional option
type Option func(*jwkd) error

// WithAthenzURL returns an AthenzURL functional option
func WithAthenzURL(url string) Option {
	return func(j *jwkd) error {
		u := urlutil.TrimHTTPScheme(url)
		if urlutil.HasScheme(u) {
			return urlutil.ErrUnsupportedScheme
		}
		j.athenzURL = u
		return nil
	}
}

// WithRefreshPeriod returns a RefreshPeriod functional option
func WithRefreshPeriod(t string) Option {
	return func(j *jwkd) error {
		if t == "" {
			return nil
		}
		rd, err := time.ParseDuration(t)
		if err != nil {
			return errors.Wrap(err, "invalid refresh period")
		}
		j.refreshPeriod = rd
		return nil
	}
}

// WithRetryDelay returns an RetryDelay functional option
func WithRetryDelay(i string) Option {
	return func(j *jwkd) error {
		if i == "" {
			return nil
		}
		ri, err := time.ParseDuration(i)
		if err != nil {
			return errors.Wrap(err, "invalid retry delay")
		}
		j.retryDelay = ri
		return nil
	}
}

// WithJwkUrls returns an JwkUrls functional option
func WithJwkUrls(jwkurls string) Option {
	return func(j *jwkd) error {
		u := urlutil.TrimHTTPScheme(jwkurls)
		if urlutil.HasScheme(u) {
			return urlutil.ErrUnsupportedScheme
		}
		j.jwkurls = u
		return nil
	}
}

// WithHTTPClient returns a HTTPClient functional option
func WithHTTPClient(cl *http.Client) Option {
	return func(j *jwkd) error {
		j.client = cl
		return nil
	}
}
