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
)

var (
	defaultOptions = []Option{
		WithRefreshDuration("24h"),
		WithErrRetryInterval("1m"),
		WithHTTPClient(http.DefaultClient),
	}
)

// Option represents a functional option
type Option func(*jwkd) error

// WithAthenzURL returns an AthenzURL functional option
func WithAthenzURL(url string) Option {
	return func(j *jwkd) error {
		if url == "" {
			return nil
		}
		j.athenzURL = url
		return nil
	}
}

// WithRefreshDuration returns a RefreshDuration functional option
func WithRefreshDuration(t string) Option {
	return func(j *jwkd) error {
		if t == "" {
			return nil
		}
		rd, err := time.ParseDuration(t)
		if err != nil {
			return errors.Wrap(err, "invalid refresh duration")
		}
		j.refreshDuration = rd
		return nil
	}
}

// WithErrRetryInterval returns an ErrRetryInterval functional option
func WithErrRetryInterval(i string) Option {
	return func(j *jwkd) error {
		if i == "" {
			return nil
		}
		ri, err := time.ParseDuration(i)
		if err != nil {
			return errors.Wrap(err, "invalid err retry interval")
		}
		j.errRetryInterval = ri
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
