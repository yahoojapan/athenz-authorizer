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
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kpango/fastime"
	"github.com/kpango/gache"
	"github.com/kpango/glg"
	"github.com/pkg/errors"
	"github.com/yahoo/athenz/utils/zpe-updater/util"
	"github.com/yahoojapan/athenz-authorizer/v3/pubkey"
	"golang.org/x/sync/errgroup"
)

// Daemon represents the daemon to retrieve policy data from Athenz.
type Daemon interface {
	Start(context.Context) <-chan error
	Update(context.Context) error
	CheckPolicy(ctx context.Context, domain string, roles []string, action, resource string) error
	GetPolicyCache(context.Context) map[string]interface{}
}

type policyd struct {

	// The rolePolicies map has the format of  map[<domain>:role.<role>][]*Assertion
	// The []*Assertion contains deny policies first, and following the allow policies
	// When CheckPolicy function called, the []*Assertion is check by order, in current implementation the deny policy is prioritize,
	// so we need to put the deny policies in lower index.
	rolePolicies gache.Gache

	expiryMargin  time.Duration // force update policy before actual expiry by margin duration
	refreshPeriod time.Duration
	purgePeriod   time.Duration
	retryDelay    time.Duration
	retryAttempts int

	athenzURL     string
	athenzDomains []string

	client   *http.Client
	pkp      pubkey.Provider
	fetchers map[string]Fetcher // used for concurrent read, should never be updated
}

// New represent the constructor of Policyd
func New(opts ...Option) (Daemon, error) {
	p := &policyd{
		rolePolicies: gache.New(),
	}

	for _, opt := range append(defaultOptions, opts...) {
		if err := opt(p); err != nil {
			return nil, errors.Wrap(err, "error create policyd")
		}
	}

	// create fetchers
	p.fetchers = make(map[string]Fetcher, len(p.athenzDomains))
	for _, domain := range p.athenzDomains {
		f := fetcher{
			domain:        domain,
			expiryMargin:  p.expiryMargin,
			retryDelay:    p.retryDelay,
			retryAttempts: p.retryAttempts,
			athenzURL:     p.athenzURL,
			spVerifier: func(sp *SignedPolicy) error {
				return sp.Verify(p.pkp)
			},
			client: p.client,
		}
		p.fetchers[domain] = &f
	}

	return p, nil
}

// Start starts the Policy daemon to retrive the policy data periodically
func (p *policyd) Start(ctx context.Context) <-chan error {
	glg.Info("Starting policyd updater")
	ech := make(chan error, 100)
	fch := make(chan struct{}, 1)

	go func() {
		defer close(fch)
		defer close(ech)

		ticker := time.NewTicker(p.refreshPeriod)
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

					time.Sleep(p.retryDelay)

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
	jobID := fastime.Now().Unix()
	glg.Infof("[%d] will update policy", jobID)
	eg := errgroup.Group{}
	rp := gache.New()

	for _, fetcher := range p.fetchers {
		f := fetcher // for closure
		select {
		case <-ctx.Done():
			glg.Info("Update policy interrupted")
			return ctx.Err()
		default:
			eg.Go(func() error {
				select {
				case <-ctx.Done():
					glg.Info("Update policy interrupted")
					return ctx.Err()
				default:
					return fetchAndCachePolicy(ctx, rp, f)
				}
			})
		}
	}

	if err := eg.Wait(); err != nil {
		glg.Errorf("[%d] update policy fail", jobID)
		return err
	}

	rp.StartExpired(ctx, p.purgePeriod).
		EnableExpiredHook().
		SetExpiredHook(func(ctx context.Context, key string) {
			// key = <domain>:role.<role>
			fetchAndCachePolicy(ctx, p.rolePolicies, p.fetchers[strings.Split(key, ":role.")[0]])
		})

	p.rolePolicies, rp = rp, p.rolePolicies
	glg.Debugf("tmp cache becomes effective")
	rp.Stop()
	rp.Clear()

	glg.Infof("[%d] update policy done", jobID)
	return nil
}

// CheckPolicy checks the specified request has privilege to access the resources or not.
// If return is nil then the request is allowed, otherwise the request is rejected.
// Only action and resource is supporting wildcard, domain and role is not supporting wildcard.
func (p *policyd) CheckPolicy(ctx context.Context, domain string, roles []string, action, resource string) error {
	ech := make(chan error, len(roles))
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		defer close(ech)

		wg := new(sync.WaitGroup)
		wg.Add(len(roles))
		rp := p.rolePolicies

		for _, role := range roles {
			dr := fmt.Sprintf("%s:role.%s", domain, role)
			go func(ch chan<- error) {
				defer wg.Done()
				select {
				case <-cctx.Done():
					ch <- cctx.Err()
					return
				default:
					asss, ok := rp.Get(dr)
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
							// deny policies come first in rolePolicies, so it will return first before allow policies is checked
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
	}()

	allowed := false
	for err := range ech {
		if err != nil { // denied assertion is prioritize, so return directly
			glg.Debugf("check policy domain: %s, role: %v, action: %s, resource: %s, result: %v", domain, roles, action, resource, err)
			return err
		}
		allowed = true
	}
	if allowed {
		glg.Debugf("check policy domain: %s, role: %v, action: %s, resource: %s, result: %v", domain, roles, action, resource, nil)
		return nil
	}
	err := errors.Wrap(ErrNoMatch, "no match")
	glg.Debugf("check policy domain: %s, role: %v, action: %s, resource: %s, result: %v", domain, roles, action, resource, err)
	return err
}

// GetPolicyCache returns the cached role policy data
func (p *policyd) GetPolicyCache(ctx context.Context) map[string]interface{} {
	return p.rolePolicies.ToRawMap(ctx)
}

func fetchAndCachePolicy(ctx context.Context, g gache.Gache, f Fetcher) error {
	sp, err := f.FetchWithRetry(ctx)
	if err != nil {
		errMsg := "fetch policy fail"
		glg.Errorf("%s, error: %v", errMsg, err)
		if sp == nil {
			return errors.Wrap(err, errMsg)
		}
	}

	glg.DebugFunc(func() string {
		rawpol, _ := json.Marshal(sp)
		return fmt.Sprintf("will merge policy, domain: %s, body: %s", f.Domain(), (string)(rawpol))
	})

	if err := simplifyAndCachePolicy(ctx, g, sp); err != nil {
		errMsg := "simplify and cache policy fail"
		glg.Debugf("%s, error: %v", errMsg, err)
		return errors.Wrap(err, errMsg)
	}

	return nil
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
	now := fastime.Now()
	assm.Range(func(k interface{}, val interface{}) bool {
		ass := val.(*util.Assertion)
		a, err := NewAssertion(ass.Action, ass.Resource, ass.Effect)
		if err != nil {
			glg.Debugf("error adding assertion to the cache, err: %v", err)
			retErr = err
			return false
		}

		var asss []*Assertion
		if p, ok := rp.Get(ass.Role); ok {
			asss = p.([]*Assertion)
			if a.Effect == nil {
				asss = append(asss, a) // append allowed policies to the end of the slice
			} else {
				asss = append([]*Assertion{a}, asss...) // append denied policies to the head
			}
		} else {
			asss = []*Assertion{a}
		}
		rp.SetWithExpire(ass.Role, asss, sp.DomainSignedPolicyData.SignedPolicyData.Expires.Sub(now))

		glg.Debugf("added assertion to the tmp cache: %+v", ass)
		return true
	})
	if retErr != nil {
		return retErr
	}

	return nil
}
