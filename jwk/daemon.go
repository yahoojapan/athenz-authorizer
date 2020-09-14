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
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/kpango/glg"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"
)

// Daemon represents the daemon to retrieve jwk from Athenz.
type Daemon interface {
	Start(ctx context.Context) <-chan error
	Update(context.Context) error
	GetProvider() Provider
}

type jwkd struct {
	athenzJwksURL string
	urls          []string

	refreshPeriod time.Duration
	retryDelay    time.Duration

	client *http.Client

	keys *sync.Map
}

// Provider represent the jwk provider to retrieve the json web key.
type Provider func(keyID string, jwkSetURL string) interface{}

// New represent the constructor of Policyd
func New(opts ...Option) (Daemon, error) {
	j := &jwkd{
		keys: &sync.Map{},
	}
	for _, opt := range append(defaultOptions, opts...) {
		err := opt(j)
		if err != nil {
			return nil, errors.Wrap(err, "error create jwkd")
		}
	}

	return j, nil
}

func (j *jwkd) Start(ctx context.Context) <-chan error {
	glg.Info("Starting jwk updater")
	ech := make(chan error, 100)
	fch := make(chan struct{}, 1)

	go func() {
		defer close(fch)
		defer close(ech)
		ticker := time.NewTicker(j.refreshPeriod)
		ebuf := errors.New("")

		update := func() {
			if err := j.Update(ctx); err != nil {
				err = errors.Wrap(err, "error update athenz json web key")
				time.Sleep(j.retryDelay)

				select {
				case ech <- errors.Wrap(ebuf, err.Error()):
					ebuf = errors.New("")
				default:
					ebuf = errors.Wrap(ebuf, err.Error())
				}

				select {
				case fch <- struct{}{}:
				default:
					glg.Warn("failure queue already full")
				}
			}
		}

		for {
			select {
			case <-ctx.Done():
				glg.Info("Stopping jwkd")
				ticker.Stop()
				if ebuf.Error() != "" {
					ech <- errors.Wrap(ctx.Err(), ebuf.Error())
				} else {
					ech <- ctx.Err()
				}
				return
			case <-fch:
				update()
			case <-ticker.C:
				update()
			}
		}
	}()

	return ech
}

func (j *jwkd) Update(ctx context.Context) (err error) {
	glg.Info("Fetching JWK Set")

	var targets []string
	if !isContain(j.urls, j.athenzJwksURL) {
		targets = append([]string{j.athenzJwksURL}, j.urls...)
	} else {
		targets = j.urls
	}

	var failedTargets []string
	for _, target := range targets {
		glg.Debugf("Fetching JWK Set from %s", target)
		keys, err := jwk.FetchHTTP(target, jwk.WithHTTPClient(j.client))
		if err != nil {
			glg.Errorf("Fetch JWK Set error: %v", err)
			failedTargets = append(failedTargets, target)
			continue
		}
		j.keys.Store(target, keys)
		glg.Debugf("Fetch JWK Set from %s success", target)
	}

	if len(failedTargets) > 0 {
		return errors.Errorf("Failed to fetch the JWK Set from these URLs: %s", failedTargets)
	}

	glg.Info("Fetch JWK Set success")
	return nil
}

func (j *jwkd) GetProvider() Provider {
	return j.getKey
}

func (j *jwkd) getKey(keyID string, jwkSetURL string) interface{} {
	if keyID == "" {
		return nil
	}

	var keys interface{}
	var ok bool
	if jwkSetURL == "" {
		keys, ok = j.keys.Load(j.athenzJwksURL)
	} else {
		keys, ok = j.keys.Load(jwkSetURL)
	}

	// Either jku specified in the token is not set in jwkd.urls or key cache is failing.
	if !ok {
		return nil
	}

	for _, key := range keys.(*jwk.Set).LookupKeyID(keyID) {
		var raw interface{}
		if err := key.Raw(&raw); err != nil {
			glg.Warnf("jwkd.getKey: %s", err.Error())
		} else {
			return raw
		}
	}
	// Either key for the kid specified in the token was not found or invalid key
	return nil
}

func isContain(targets []string, key string) bool {
	for _, target := range targets {
		if target == key {
			return true
		}
	}
	return false
}
