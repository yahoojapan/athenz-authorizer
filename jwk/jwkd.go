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
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/kpango/gache"
	"github.com/kpango/glg"
	"github.com/pkg/errors"
)

type JWKD interface {
	Start(ctx context.Context) <-chan error
	Update(context.Context) error
	GetProvider() Provider
}

type jwkd struct {
	athenzURL        string
	refreshDuration  time.Duration
	errRetryInterval time.Duration

	client *http.Client

	pubkeys gache.Gache

	etagCache    gache.Gache
	etagExpTime  time.Duration
	etagFlushDur time.Duration
}

// Provider represent the jwk provider to retrive the json web key.
type Provider func(alg, keyID string) string

type jwkCache struct {
	eTag string
	keys *JWK
}

const (
	jwkEtagKey = "jwk"
)

// New represent the constructor of Policyd
func New(opts ...Option) (JWKD, error) {
	p := &jwkd{
		rolePolicies: gache.New(),
		etagCache:    gache.New(),
	}

	p.rolePolicies.EnableExpiredHook().SetExpiredHook(func(ctx context.Context, key string) {
		//key = <domain>:role.<role>
		p.fetchAndCachePolicy(ctx, strings.Split(key, ":role.")[0])
	})

	for _, opt := range append(defaultOptions, opts...) {
		err := opt(p)
		if err != nil {
			return nil, errors.Wrap(err, "error create policyd")
		}
	}

	return p, nil
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
		j.etagCache.StartExpired(ctx, j.etagFlushDur)
		ticker := time.NewTicker(j.refreshDuration)
		ebuf := errors.New("")
		for {
			select {
			case <-ctx.Done():
				glg.Info("Stopping pubkeyd")
				ticker.Stop()
				if ebuf.Error() != "" {
					ech <- errors.Wrap(ctx.Err(), ebuf.Error())
				} else {
					ech <- ctx.Err()
				}
				return
			case <-fch:
				if err := c.Update(ctx); err != nil {
					err = errors.Wrap(err, "error update athenz json web key")
					select {
					case ech <- errors.Wrap(ebuf, err.Error()):
						ebuf = errors.New("")
					default:
						ebuf = errors.Wrap(ebuf, err.Error())
					}
					time.Sleep(j.errRetryInterval)
					select {
					case fch <- struct{}{}:
					default:
						glg.Warn("failure queue already full")
					}
				}
			case <-ticker.C:
				if err := c.Update(ctx); err != nil {
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
		}
	}()

	return ech

}
func (j *jwkd) Update(ctx context.Context) error {
	return nil
}
func (j *jwkd) GetProvider() Provider {
	return nil
}

func (j *jwkd) fetchJWK(ctx context.Context) (*JWK, error) {
	url := fmt.Sprintf("https://%s/oauth2/keys", j.athenzURL)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		glg.Errorf("Fetch json web key entries error: %v", err)
		return nil, errors.Wrap(err, "error creating get jwk request")
	}

	// etag header
	t, ok := j.etagCache.Get(jwkEtagKey)
	if ok {
		eTag := t.(*jwkCache).eTag
		glg.Debugf("ETag %v found in the cache", eTag)
		req.Header.Set("If-None-Match", eTag)
	}

	r, err := j.client.Do(req.WithContext(ctx))
	if err != nil {
		glg.Errorf("Error making HTTP request, error: %v", err)
		return nil, errors.Wrap(err, "error make http request")
	}

	// if server return NotModified, return policy from cache
	if r.StatusCode == http.StatusNotModified {
		cache := t.(*jwkCache)
		glg.Debugf("Server return not modified, etag: ", cache.eTag)
		return cache.keys, nil
	}

	// if server return any error
	if r.StatusCode != http.StatusOK {
		glg.Error("Server return not OK")
		return nil, errors.Wrap(ErrFetchAthenzJWK, "http return status not OK")
	}

	keys := new(JWK)
	if err = json.NewDecoder(r.Body).Decode(&keys); err != nil {
		glg.Errorf("Error decoding public key entries, err: %v", err)
		return nil, errors.Wrap(err, "json format not correct")
	}

	if _, err = io.Copy(ioutil.Discard, r.Body); err != nil {
		glg.Warn(errors.Wrap(err, "error io.copy"))
	}

	if err = r.Body.Close(); err != nil {
		glg.Warn(errors.Wrap(err, "error body.close"))
	}

	// set eTag cache
	eTag := r.Header.Get("ETag")
	if eTag != "" {
		glg.Debugf("Setting ETag %v", eTag)
		j.etagCache.SetWithExpire(jwkEtagKey, &jwkCache{eTag, keys}, j.etagExpTime)
	}

	glg.Info("Fetch json web key entries success")

	return nil, nil
}
