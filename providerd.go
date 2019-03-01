package providerd

import (
	"context"
	"crypto/x509"
	"net/http"
	"time"

	"github.com/kpango/gache"
	"github.com/kpango/glg"

	"github.com/yahoojapan/athenz-policy-updater/role"
	"github.com/pkg/errors"

	"github.com/yahoojapan/athenz-policy-updater/config"
	"github.com/yahoojapan/athenz-policy-updater/policy"
)

// TokenService represents a interface for user to get the token, and automatically update the token
type Providerd interface {
	StartProviderd(context.Context) <-chan error
	VerifyRoleToken(ctx context.Context, tok, act, res string) error
	VerifyRoleCert(cert []*x509.Certificate) error
}

type provider struct {
	//
	athenzConfd     config.AthenzConfd
	policyd         policy.Policyd
	roleTokenParser role.RoleTokenParser

	// common parameters
	athenzURL string
	client    *http.Client

	// result cache
	cache    gache.Gache
	cacheExp time.Duration

	// athenzConfd parameters
	athenzConfRefreshDuration string
	athenzConfSysAuthDomain   string
	athenzConfEtagExpTime     string
	athenzConfEtagFlushDur    string

	// policyd parameters
	policyExpireMargin    string
	athenzDomains         []string
	policyRefreshDuration string
	policyEtagFlushDur    string
	policyEtagExpTime     string
}

// New return TokenService
// This function will initialize the TokenService object with the tokenOptions
func New(opts ...Option) (Providerd, error) {
	prov := &provider{}
	var err error
	for _, opt := range append(defaultOptions, opts...) {
		if err = opt(prov); err != nil {
			return nil, errors.Wrap(err, "error creating providerd")
		}
	}

	if prov.athenzConfd, err = config.NewAthenzConfd(
		config.AthenzURL(prov.athenzURL),
		config.SysAuthDomain(prov.athenzConfSysAuthDomain),
		config.ETagExpTime(prov.athenzConfEtagExpTime),
		config.ETagFlushDur(prov.athenzConfEtagFlushDur),
		config.RefreshDuration(prov.athenzConfRefreshDuration),
		config.HttpClient(prov.client),
	); err != nil {
		return nil, errors.Wrap(err, "error create athenzConfd")
	}

	if prov.policyd, err = policy.NewPolicyd(
		policy.ExpireMargin(prov.policyExpireMargin),
		policy.EtagFlushDur(prov.policyEtagFlushDur),
		policy.EtagExpTime(prov.policyEtagExpTime),
		policy.AthenzURL(prov.athenzURL),
		policy.AthenzDomains(prov.athenzDomains),
		policy.RefreshDuration(prov.policyRefreshDuration),
		policy.HttpClient(prov.client),
		policy.PubKeyProvider(prov.athenzConfd.GetPubKeyProvider()),
	); err != nil {
		return nil, errors.Wrap(err, "error create policyd")
	}

	prov.roleTokenParser = role.NewRoleTokenParser(prov.athenzConfd.GetPubKeyProvider())

	return prov, nil
}

func (p *provider) StartProviderd(ctx context.Context) <-chan error {
	ech := make(chan error)

	go func() {
		// TODO expose set expire daemon duration interface
		p.cache.StartExpired(ctx, p.cacheExp/10)

		cech := p.athenzConfd.StartConfUpdator(ctx)
		pech := p.policyd.StartPolicyUpdator(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case err := <-cech:
				if err != nil {
					ech <- errors.Wrap(err, "update athenz conf error")
				}
			case err := <-pech:
				if err != nil {
					ech <- errors.Wrap(err, "update policy error")
				}
			}
		}
	}()

	return ech
}

func (p *provider) VerifyRoleToken(ctx context.Context, tok, act, res string) error {
	if act == "" || res == "" {
		return errors.Wrap(ErrInvalidParameters, "empty action / resource")
	}
	_, ok := p.cache.Get(tok + act + res)
	if ok {
		glg.Debugf("use cached roletoken result. tok: %s, act: %s, res: %s", tok, act, res)
		return nil
	}

	rt, err := p.roleTokenParser.ParseAndValidateRoleToken(tok)
	if err != nil {
		glg.Debugf("error parse and validate role token, err: %v", err)
		return errors.Wrap(err, "error verify role token")
	}
	if err = p.policyd.CheckPolicy(ctx, rt.Domain, rt.Roles, act, res); err != nil {
		glg.Debugf("error check, err: %v", err)
		return errors.Wrap(err, "role token unauthorizate")
	}
	glg.Debugf("set roletoken result. tok: %s, act: %s, res: %s", tok, act, res)
	p.cache.SetWithExpire(tok+act+res, struct{}{}, p.cacheExp)
	return nil
}

func (p *provider) VerifyRoleCert(cert []*x509.Certificate) error {
	return nil
}