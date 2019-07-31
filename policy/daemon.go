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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kpango/gache"
	"github.com/kpango/glg"
	"github.com/pkg/errors"
	"github.com/yahoo/athenz/utils/zpe-updater/util"
	"github.com/yahoojapan/athenz-authorizer/pubkey"
	"golang.org/x/sync/errgroup"
)

// Policyd represent the daemon to retrieve policy data from Athenz.
type Daemon interface {
	Start(context.Context) <-chan error
	Update(context.Context) error
	CheckPolicy(ctx context.Context, domain string, roles []string, action, resource string) error
	GetPolicyCache(context.Context) map[string]interface{}
}

type policyd struct {
	expireMargin          time.Duration // expire margin force update policy when the policy expire time hit the margin
	rolePolicies          gache.Gache   //*sync.Map // map[<domain>:role.<role>][]Assertion
	policyExpiredDuration time.Duration

	refreshDuration time.Duration
	//flushDur time.Duration
	errRetryInterval time.Duration

	pkp pubkey.Provider

	etagCache    gache.Gache
	etagFlushDur time.Duration
	etagExpTime  time.Duration

	// www.athenz.com/zts/v1
	athenzURL     string
	athenzDomains []string

	client *http.Client
}

type etagCache struct {
	eTag string
	sp   *SignedPolicy
}

// New represent the constructor of Policyd
func New(opts ...Option) (Daemon, error) {
	p := &policyd{
		rolePolicies: gache.New(),
		etagCache:    gache.New(),
	}

	for _, opt := range append(defaultOptions, opts...) {
		if err := opt(p); err != nil {
			return nil, errors.Wrap(err, "error create policyd")
		}
	}

	return p, nil
}

// Start starts the Policy daemon to retrive the policy data periodically
func (p *policyd) Start(ctx context.Context) <-chan error {
	glg.Info("Starting policyd updater")
	ech := make(chan error, 100)
	fch := make(chan struct{}, 1)
	if err := p.Update(ctx); err != nil {
		glg.Debugf("Error initialize policy data, err: %v", err)
		ech <- errors.Wrap(err, "error update policy")
		fch <- struct{}{}
	}

	go func() {
		defer close(fch)
		defer close(ech)

		p.etagCache.StartExpired(ctx, p.etagFlushDur)
		ticker := time.NewTicker(p.refreshDuration)
		for {
			select {
			case <-ctx.Done():
				glg.Info("Stopping policyd updater")
				ticker.Stop()
				ech <- ctx.Err()
				return
			case <-fch:
				if err := p.Update(ctx); err != nil {
					ech <- errors.Wrap(err, "error update policy")

					time.Sleep(p.errRetryInterval)

					select {
					case fch <- struct{}{}:
					default:
						glg.Warn("failure queue already full")
					}
				}
			case <-ticker.C:
				if err := p.Update(ctx); err != nil {
					ech <- errors.Wrap(err, "error update policy")

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

// Update updates and cache policy data
func (p *policyd) Update(ctx context.Context) error {
	glg.Info("Updating policy")
	defer glg.Info("Updated policy")
	eg := errgroup.Group{}
	rp := gache.New()

	for _, domain := range p.athenzDomains {
		select {
		case <-ctx.Done():
			glg.Info("Update policy interrupted")
			return ctx.Err()
		default:
			dom := domain
			eg.Go(func() error {
				select {
				case <-ctx.Done():
					glg.Info("Update policy interrupted")
					return ctx.Err()
				default:
					return p.fetchAndCachePolicy(ctx, rp, dom)
				}
			})
		}
	}

	if err := eg.Wait(); err != nil {
		return err
	}

	rp.StartExpired(ctx, p.policyExpiredDuration).
		EnableExpiredHook().
		SetExpiredHook(func(ctx context.Context, key string) {
			//key = <domain>:role.<role>
			p.fetchAndCachePolicy(ctx, p.rolePolicies, strings.Split(key, ":role.")[0])
		})

	p.rolePolicies, rp = rp, p.rolePolicies
	rp.Stop()
	rp.Clear()

	return nil
}

// CheckPolicy checks the specified request has privilege to access the resources or not.
// If return is nil then the request is allowed, otherwise the request is rejected.
func (p *policyd) CheckPolicy(ctx context.Context, domain string, roles []string, action, resource string) error {
	ech := make(chan error, len(roles))
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		defer close(ech)
		wg := new(sync.WaitGroup)
		for _, role := range roles {
			dr := fmt.Sprintf("%s:role.%s", domain, role)
			wg.Add(1)
			go func(ch chan<- error) {
				defer wg.Done()
				select {
				case <-cctx.Done():
					ch <- cctx.Err()
					return
				default:
					asss, ok := p.rolePolicies.Get(dr)
					if !ok {
						return
					}

					for _, ass := range asss.([]*Assertion) {
						glg.Debugf("Checking policy domain: %s, role: %v, action: %s, resource: %s, assertion: %v", domain, roles, action, resource, ass)
						select {
						case <-cctx.Done():
							ch <- cctx.Err()
							return
						default:
							if strings.EqualFold(ass.ResourceDomain, domain) && ass.Reg.MatchString(strings.ToLower(action+"-"+resource)) {
								ch <- ass.Effect
								return
							}
						}
					}
				}
			}(ech)
		}
		wg.Wait()
		ech <- errors.Wrap(ErrNoMatch, "no match")
	}()

	err := <-ech

	glg.Debugf("check policy domain: %s, role: %v, action: %s, resource: %s, result: %v", domain, roles, action, resource, err)
	return err
}

func (p *policyd) GetPolicyCache(ctx context.Context) map[string]interface{} {
	return p.rolePolicies.ToRawMap(ctx)
}

func (p *policyd) fetchAndCachePolicy(ctx context.Context, g gache.Gache, dom string) error {
	spd, upd, err := p.fetchPolicy(ctx, dom)
	if err != nil {
		glg.Debugf("fetch policy failed, err: %v", err)
		return errors.Wrap(err, "error fetch policy")
	}

	glg.DebugFunc(func() string {
		rawpol, _ := json.Marshal(spd)
		return fmt.Sprintf("fetched policy data, domain: %s,updated: %v, body: %s", dom, upd, (string)(rawpol))
	})

	if err = simplifyAndCachePolicy(ctx, g, spd); err != nil {
		glg.Debugf("simplify and cache error: %v", err)
		return errors.Wrap(err, "error simplify and cache")
	}

	return nil
}

func (p *policyd) fetchPolicy(ctx context.Context, domain string) (*SignedPolicy, bool, error) {
	glg.Infof("Fetching policy for domain %s", domain)
	// https://{www.athenz.com/zts/v1}/domain/{athenz domain}/signed_policy_data
	url := fmt.Sprintf("https://%s/domain/%s/signed_policy_data", p.athenzURL, domain)

	glg.Debugf("fetching policy, url: %v", url)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		glg.Errorf("fetch policy error, domain: %s, error: %v", domain, err)
		return nil, false, errors.Wrap(err, "error creating fetch policy request")
	}

	// etag header
	t, ok := p.etagCache.Get(domain)
	if ok {
		ec := t.(*etagCache)
		if time.Now().Add(p.expireMargin).UnixNano() < ec.sp.SignedPolicyData.Expires.UnixNano() {
			glg.Debugf("domain: %s, using etag: %s", domain, ec.eTag)
			req.Header.Set("If-None-Match", ec.eTag)
		}
	}

	res, err := p.client.Do(req.WithContext(ctx))
	if err != nil {
		glg.Errorf("Error making HTTP request, domain: %s, error: %v", domain, err)
		return nil, false, errors.Wrap(err, "error making request")
	}

	// if server return NotModified, return policy from cache
	if res.StatusCode == http.StatusNotModified {
		cache := t.(*etagCache)
		glg.Debugf("Server return not modified, domain: %s, etag: %v", domain, cache.eTag)
		return cache.sp, false, nil
	}

	if res.StatusCode != http.StatusOK {
		glg.Errorf("Domain %s: Server return not OK", domain)
		return nil, false, errors.Wrap(ErrFetchPolicy, "error fetching policy data")
	}

	// read and decode
	sp := new(SignedPolicy)
	if err = json.NewDecoder(res.Body).Decode(&sp); err != nil {
		glg.Errorf("Error decoding policy, domain: %s, err: %v", domain, err)
		return nil, false, errors.Wrap(err, "error decode response")
	}

	// verify policy data
	if err = sp.Verify(p.pkp); err != nil {
		glg.Errorf("Error verifying policy, domain: %s,err: %v", domain, err)
		return nil, false, errors.Wrap(err, "error verify policy data")
	}

	if _, err = io.Copy(ioutil.Discard, res.Body); err != nil {
		glg.Warn(errors.Wrap(err, "error io.copy"))
	}
	if err = res.Body.Close(); err != nil {
		glg.Warn(errors.Wrap(err, "error body.close"))
	}

	// set eTag cache
	eTag := res.Header.Get("ETag")
	if eTag != "" {
		glg.Debugf("Setting ETag %v for domain %s", eTag, domain)

		dur := sp.SignedPolicyData.Expires.Sub(time.Now())
		if dur <= 0 {
			dur = p.etagExpTime
		}
		p.etagCache.SetWithExpire(domain, &etagCache{eTag, sp}, dur)
	}

	return sp, true, nil
}

func simplifyAndCachePolicy(ctx context.Context, rp gache.Gache, sp *SignedPolicy) error {
	eg := errgroup.Group{}
	assm := new(sync.Map) // assertion map

	// simplify signed policy cache
	for _, policy := range sp.DomainSignedPolicyData.SignedPolicyData.PolicyData.Policies {
		pol := policy
		eg.Go(func() error {
			for _, ass := range pol.Assertions {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
					km := fmt.Sprintf("%s,%s,%s", ass.Role, ass.Action, ass.Resource)
					if _, ok := assm.Load(km); !ok {
						assm.Store(km, ass)
					} else {
						// deny policy will override allow policy, and also remove duplication
						if strings.EqualFold("deny", ass.Effect) {
							assm.Store(km, ass)
						}
					}
				}
			}

			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		return errors.Wrap(err, "error simplify and cache policy")
	}

	// cache
	var retErr error
	assm.Range(func(k interface{}, val interface{}) bool {
		ass := val.(*util.Assertion)
		a, err := NewAssertion(ass.Action, ass.Resource, ass.Effect)
		if err != nil {
			glg.Debugf("error adding assertion to the cache, err: %v", err)
			retErr = err
			return false
		}

		var asss []*Assertion
		r := ass.Role
		if r, ok := rp.Get(r); ok {
			asss = append(r.([]*Assertion), a)
		} else {
			asss = []*Assertion{a}
		}
		rp.SetWithExpire(ass.Role, asss, time.Duration(sp.DomainSignedPolicyData.SignedPolicyData.Expires.UnixNano()))

		glg.Debugf("added assertion to the cache: %+v", ass)
		return true
	})
	if retErr != nil {
		return retErr
	}

	return nil
}
