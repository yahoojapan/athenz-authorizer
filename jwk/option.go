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
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"
	urlutil "github.com/yahoojapan/athenz-authorizer/v5/internal/url"
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

// WithAthenzJwksURL returns an Athenz JWK URL path functional option
func WithAthenzJwksURL(url string) Option {
	return func(j *jwkd) error {
		if url == "" {
			return urlutil.ErrEmptyAthenzJwksURL
		}
		u := urlutil.TrimHTTPScheme(url)
		if urlutil.HasScheme(u) {
			return urlutil.ErrUnsupportedScheme
		}
		j.athenzJwksURL = fmt.Sprintf("https://%s/oauth2/keys", u)
		if j.athenzJwksRFC {
			j.athenzJwksURL += "?rfc=true"
		}
		return nil
	}
}

// WithAthenzJwksRFC returns an Athenz JWK RFC functional option
func WithAthenzJwksRFC(rfc bool) Option {
	return func(j *jwkd) error {
		j.athenzJwksRFC = rfc

		// If this option is invoked after WithAthenzJwksURL, fix up the athenzJwksURL
		if j.athenzJwksURL != "" {
			j.athenzJwksURL = strings.TrimSuffix(j.athenzJwksURL, "?rfc=true")
			if rfc {
				j.athenzJwksURL += "?rfc=true"
			}
		}

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

// WithURLs returns an JwkUrls functional option
func WithURLs(urls []string) Option {
	return func(j *jwkd) error {
		for _, targetURL := range urls {
			u, err := url.ParseRequestURI(targetURL)
			if err != nil {
				return err
			}
			if u.Scheme != "http" && u.Scheme != "https" {
				return urlutil.ErrUnsupportedScheme
			}
		}
		j.urls = urls
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
