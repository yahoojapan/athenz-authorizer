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
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/kpango/glg"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"
)

type Daemon interface {
	Start(ctx context.Context) <-chan error
	Update(context.Context) error
	GetProvider() Provider
}

type jwkd struct {
	athenzURL        string
	refreshDuration  time.Duration
	errRetryInterval time.Duration

	client *http.Client

	keys atomic.Value
}

// Provider represent the jwk provider to retrive the json web key.
type Provider func(keyID string) interface{}

// New represent the constructor of Policyd
func New(opts ...Option) (Daemon, error) {
	j := new(jwkd)
	for _, opt := range append(defaultOptions, opts...) {
		err := opt(j)
		if err != nil {
			return nil, errors.Wrap(err, "error create policyd")
		}
	}

	return j, nil
}

func (j *jwkd) Start(ctx context.Context) <-chan error {
	glg.Info("Starting jwk updator")
	ech := make(chan error, 100)
	fch := make(chan struct{}, 1)
	if err := j.Update(ctx); err != nil {
		ech <- errors.Wrap(err, "error update athenz json web key")
		fch <- struct{}{}
	}

	go func() {
		defer close(fch)
		defer close(ech)
		ticker := time.NewTicker(j.refreshDuration)
		ebuf := errors.New("")

		update := func() {
			if err := j.Update(ctx); err != nil {
				err = errors.Wrap(err, "error update athenz json web key")
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
	url := fmt.Sprintf("https://%s/oauth2/keys", j.athenzURL)
	keys, err := jwk.Fetch(url, jwk.WithHTTPClient(j.client))
	if err != nil {
		return err
	}

	j.keys.Store(keys)

	return nil
}

func (j *jwkd) GetProvider() Provider {
	return func(keyID string) interface{} {
		for _, keys := range j.keys.Load().(*jwk.Set).LookupKeyID(keyID) {
			raw, err := keys.Materialize()
			if err == nil {
				return raw
			}
		}
		return nil
	}
}
