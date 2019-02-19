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

	"github.com/yahoojapan/athenz-policy-updater/config"
	"github.com/kpango/gache"
	"github.com/kpango/glg"
	"github.com/pkg/errors"
	"github.com/yahoo/athenz/utils/zpe-updater/util"
	"golang.org/x/sync/errgroup"
)

type Policyd interface {
	StartPolicyUpdator(context.Context) <-chan error
	UpdatePolicy(context.Context) error
	CheckPolicy(ctx context.Context, domain string, roles []string, action, resource string) error
	GetRawPolicies() map[string]*util.PolicyData // map[Domain]map[Role][]Assertion
}

type policy struct {
	expireMargin    time.Duration // expire margin force update policy when the policy expire time hit the margin
	rolePolicies    gache.Gache   //*sync.Map // map[<domain>:role.<role>][]Assertion
	policies        map[string]*util.PolicyData
	refreshDuration time.Duration

	pkp config.PubKeyProvider

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

func NewPolicyd(opts ...Option) (Policyd, error) {
	p := &policy{
		policies:     make(map[string]*util.PolicyData),
		rolePolicies: gache.New(), //new(sync.Map),
		etagCache:    gache.New(),
		etagExpTime:  3 * time.Hour, // TODO
		client:       &http.Client{},
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

func (p *policy) StartPolicyUpdator(ctx context.Context) <-chan error {
	glg.Info("Starting policyd updator")

	ech := make(chan error)

	go func(ch chan<- error) {
		fch := make(chan struct{})
		defer close(fch)
		defer close(ch)
		p.etagCache.StartExpired(ctx, p.etagFlushDur)
		p.rolePolicies.StartExpired(ctx, time.Hour*24)

		if err := p.UpdatePolicy(ctx); err != nil {
			ch <- errors.Wrap(err, "error update policy")
			fch <- struct{}{}
		}

		ticker := time.NewTicker(p.refreshDuration)
		for {
			select {
			case <-ctx.Done():
				glg.Info("Stopping policyd updator")
				ticker.Stop()
				ch <- ctx.Err()
				return
			case <-fch:
				if err := p.UpdatePolicy(ctx); err != nil {
					ch <- errors.Wrap(err, "error update policy")
					time.Sleep(time.Minute)
					fch <- struct{}{}
				}
			case <-ticker.C:
				if err := p.UpdatePolicy(ctx); err != nil {
					ch <- errors.Wrap(err, "error update policy")
					fch <- struct{}{}
				}
			}
		}
	}(ech)

	return ech
}

func (p *policy) UpdatePolicy(ctx context.Context) error {
	glg.Info("Updating policy")
	defer glg.Info("Updated policy")
	eg := errgroup.Group{}

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
					return p.fetchAndCachePolicy(ctx, dom)
				}
			})
		}
	}

	return eg.Wait()
}

func (p *policy) CheckPolicy(ctx context.Context, domain string, roles []string, action, resource string) error {
	ech := make(chan error, 1)
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

func (p *policy) GetRawPolicies() map[string]*util.PolicyData {
	return p.policies
}

func (p *policy) fetchAndCachePolicy(ctx context.Context, dom string) error {
	spd, upd, err := p.fetchPolicy(ctx, dom)

	if err != nil {
		return errors.Wrap(err, "error fetch policy")
	}

	if upd {
		rawpol, _ := json.Marshal(spd)
		glg.Debugf("fetched policy data:\tdomain\t%s\tbody\t%s", dom, (string)(rawpol))

		if err = p.simplifyAndCache(ctx, spd); err != nil {
			return errors.Wrap(err, "error simplify and cache")
		}

		p.policies[dom] = spd.DomainSignedPolicyData.SignedPolicyData.PolicyData
	}

	return nil
}

func (p *policy) fetchPolicy(ctx context.Context, domain string) (*SignedPolicy, bool, error) {
	glg.Info("Fetching policy")
	// https://{www.athenz.com/zts/v1}/domain/{athenz domain}/signed_policy_data
	url := fmt.Sprintf("https://%s/domain/%s/signed_policy_data", p.athenzURL, domain)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		glg.Errorf("Fetch policy error: %v", err)
		return nil, false, errors.Wrap(err, "error creating fetch policy request")
	}

	// etag header
	t, ok := p.etagCache.Get(domain)
	if ok {
		ec := t.(*etagCache)
		if time.Now().Add(p.expireMargin).UnixNano() < ec.sp.SignedPolicyData.Expires.UnixNano() {
			glg.Debugf("using etag: %s", ec.eTag)
			req.Header.Set("If-None-Match", ec.eTag)
		}
	}

	res, err := p.client.Do(req.WithContext(ctx))
	if err != nil {
		glg.Errorf("Error making HTTP request, error: %v", err)
		return nil, false, errors.Wrap(err, "error making request")
	}

	// if server return NotModified, return policy from cache
	if res.StatusCode == http.StatusNotModified {
		cache := t.(*etagCache)
		glg.Debugf("Server return not modified, etag: ", cache.eTag)
		return cache.sp, false, nil
	}

	if res.StatusCode != http.StatusOK {
		glg.Error("Server return not OK")
		return nil, false, errors.Wrap(ErrFetchPolicy, "error fetching policy data")
	}

	// read and decode
	sp := new(SignedPolicy)
	if err = json.NewDecoder(res.Body).Decode(&sp); err != nil {
		glg.Errorf("Error decoding policy, err: %v", err)
		return nil, false, errors.Wrap(err, "error decode response")
	}

	// verify policy data
	if err = sp.Verify(p.pkp); err != nil {
		glg.Errorf("Error verifing policy, err: %v", err)
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
		glg.Debugf("Setting ETag %v", eTag)
		p.etagCache.SetWithExpire(domain, &etagCache{eTag, sp}, p.etagExpTime)
	}

	return sp, true, nil
}

func (p *policy) simplifyAndCache(ctx context.Context, sp *SignedPolicy) error {
	rp := gache.New()
	defer rp.Clear()

	eg := errgroup.Group{}
	for _, policy := range sp.DomainSignedPolicyData.SignedPolicyData.PolicyData.Policies {
		pol := policy
		eg.Go(func() error {
			for _, ass := range pol.Assertions {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
					a, err := NewAssertion(ass.Action, ass.Resource, ass.Effect)
					if err != nil {
						return errors.Wrap(err, "error create assertion")
					}

					var asss []*Assertion
					if r, ok := rp.Get(ass.Role); ok {
						asss = append(r.([]*Assertion), a)
					} else {
						asss = []*Assertion{a}
					}
					rp.SetWithExpire(ass.Role, asss, time.Duration(sp.DomainSignedPolicyData.SignedPolicyData.Expires.UnixNano()))
				}
			}
			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		return errors.Wrap(err, "error simplify and cache policy")
	}

	rp.Foreach(ctx, func(k string, val interface{}, exp int64) bool {
		p.rolePolicies.SetWithExpire(k, val, time.Duration(exp))
		return true
	})

	p.rolePolicies.Foreach(ctx, func(k string, val interface{}, exp int64) bool {
		_, ok := rp.Get(k)
		if !ok {
			p.rolePolicies.Delete(k)
		}
		return true
	})

	return nil
}
