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
package authorizerd

import (
	"context"
	"crypto/x509"
	"net/http"
	"strings"
	"time"

	"github.com/kpango/gache"
	"github.com/kpango/glg"

	"github.com/pkg/errors"
	"github.com/yahoojapan/athenz-authorizer/jwk"
	"github.com/yahoojapan/athenz-authorizer/policy"
	"github.com/yahoojapan/athenz-authorizer/pubkey"
	"github.com/yahoojapan/athenz-authorizer/role"
)

// Authorizerd represents a daemon for user to verify the role token
type Authorizerd interface {
	Start(ctx context.Context) <-chan error
	VerifyRoleToken(ctx context.Context, tok, act, res string) error
	VerifyRoleJWT(ctx context.Context, tok, act, res string) error
	VerifyRoleCert(ctx context.Context, peerCerts []*x509.Certificate, act, res string) error
	GetPolicyCache(ctx context.Context) map[string]interface{}
}

type authorizer struct {
	//
	pubkeyd       pubkey.Daemon
	policyd       policy.Daemon
	jwkd          jwk.Daemon
	roleProcessor role.Processor

	// common parameters
	athenzURL string
	client    *http.Client

	// successful result cache
	cache    gache.Gache
	cacheExp time.Duration

	// roleCertURIPrefix
	roleCertURIPrefix string

	// pubkeyd parameters
	disablePubkeyd         bool
	pubkeyRefreshDuration  string
	pubkeyErrRetryInterval string
	pubkeySysAuthDomain    string
	pubkeyEtagExpTime      string
	pubkeyEtagFlushDur     string

	// policyd parameters
	disablePolicyd         bool
	policyExpireMargin     string
	athenzDomains          []string
	policyRefreshDuration  string
	policyErrRetryInterval string
	policyEtagFlushDur     string
	policyEtagExpTime      string

	// jwkd parameters
	disableJwkd         bool
	jwkRefreshDuration  string
	jwkErrRetryInterval string
}

type mode uint8

const (
	token mode = iota
	jwt
)

// New return Authorizerd
// This function will initialize the Authorizerd object with the options
func New(opts ...Option) (Authorizerd, error) {
	var (
		prov = &authorizer{
			cache: gache.New(),
		}
		err error

		pubkeyProvider pubkey.Provider
		jwkProvider    jwk.Provider
	)

	for _, opt := range append(defaultOptions, opts...) {
		if err = opt(prov); err != nil {
			return nil, errors.Wrap(err, "error creating authorizerd")
		}
	}

	if !prov.disablePubkeyd {
		if prov.pubkeyd, err = pubkey.New(
			pubkey.WithAthenzURL(prov.athenzURL),
			pubkey.WithSysAuthDomain(prov.pubkeySysAuthDomain),
			pubkey.WithEtagExpTime(prov.pubkeyEtagExpTime),
			pubkey.WithEtagFlushDuration(prov.pubkeyEtagFlushDur),
			pubkey.WithRefreshDuration(prov.pubkeyRefreshDuration),
			pubkey.WithErrRetryInterval(prov.pubkeyErrRetryInterval),
			pubkey.WithHTTPClient(prov.client),
		); err != nil {
			return nil, errors.Wrap(err, "error create pubkeyd")
		}

		pubkeyProvider = prov.pubkeyd.GetProvider()
	}

	if !prov.disablePolicyd {
		if prov.policyd, err = policy.New(
			policy.WithExpireMargin(prov.policyExpireMargin),
			policy.WithEtagFlushDuration(prov.policyEtagFlushDur),
			policy.WithEtagExpTime(prov.policyEtagExpTime),
			policy.WithAthenzURL(prov.athenzURL),
			policy.WithAthenzDomains(prov.athenzDomains...),
			policy.WithRefreshDuration(prov.policyRefreshDuration),
			policy.WithErrRetryInterval(prov.policyErrRetryInterval),
			policy.WithHTTPClient(prov.client),
			policy.WithPubKeyProvider(prov.pubkeyd.GetProvider()),
		); err != nil {
			return nil, errors.Wrap(err, "error create policyd")
		}
	}

	if !prov.disableJwkd {
		if prov.jwkd, err = jwk.New(
			jwk.WithAthenzURL(prov.athenzURL),
			jwk.WithRefreshDuration(prov.jwkRefreshDuration),
			jwk.WithErrRetryInterval(prov.jwkErrRetryInterval),
			jwk.WithHTTPClient(prov.client),
		); err != nil {
			return nil, errors.Wrap(err, "error create jwkd")
		}

		jwkProvider = prov.jwkd.GetProvider()
	}

	prov.roleProcessor = role.New(
		role.WithPubkeyProvider(pubkeyProvider),
		role.WithJWKProvider(jwkProvider))

	return prov, nil
}

// Start starts authorizer daemon.
func (a *authorizer) Start(ctx context.Context) <-chan error {
	var (
		ech              = make(chan error, 200)
		g                = a.cache.StartExpired(ctx, a.cacheExp/2)
		cech, pech, jech <-chan error
	)

	if !a.disablePubkeyd {
		cech = a.pubkeyd.Start(ctx)
	}
	if !a.disablePolicyd {
		pech = a.policyd.Start(ctx)
	}
	if !a.disableJwkd {
		jech = a.jwkd.Start(ctx)
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				g.Stop()
				g.Clear()
				ech <- ctx.Err()
				return
			case err := <-cech:
				if err != nil {
					ech <- errors.Wrap(err, "update pubkey error")
				}
			case err := <-pech:
				if err != nil {
					ech <- errors.Wrap(err, "update policy error")
				}
			case err := <-jech:
				if err != nil {
					ech <- errors.Wrap(err, "update jwk error")
				}
			}
		}
	}()

	return ech
}

// VerifyRoleToken verifies the role token for specific resource and return and verification error.
func (a *authorizer) VerifyRoleToken(ctx context.Context, tok, act, res string) error {
	return a.verify(ctx, token, tok, act, res)
}

func (a *authorizer) VerifyRoleJWT(ctx context.Context, tok, act, res string) error {
	return a.verify(ctx, jwt, tok, act, res)
}

func (a *authorizer) verify(ctx context.Context, m mode, tok, act, res string) error {
	if act == "" || res == "" {
		return errors.Wrap(ErrInvalidParameters, "empty action / resource")
	}

	// check if exists in verification success cache
	_, ok := a.cache.Get(tok + act + res)
	if ok {
		glg.Debugf("use cached result. tok: %s, act: %s, res: %s", tok, act, res)
		return nil
	}

	var (
		domain string
		roles  []string
	)

	switch m {
	case token:
		rt, err := a.roleProcessor.ParseAndValidateRoleToken(tok)
		if err != nil {
			glg.Debugf("error parse and validate role token, err: %v", err)
			return errors.Wrap(err, "error verify role token")
		}
		domain = rt.Domain
		roles = rt.Roles
	case jwt:
		rc, err := a.roleProcessor.ParseAndValidateRoleJWT(tok)
		if err != nil {
			glg.Debugf("error parse and validate role jwt, err: %v", err)
			return errors.Wrap(err, "error verify role jwt")
		}
		domain = rc.Domain
		roles = strings.Split(strings.TrimSpace(rc.Role), ",")
	}

	if err := a.policyd.CheckPolicy(ctx, domain, roles, act, res); err != nil {
		glg.Debugf("error check, err: %v", err)
		return errors.Wrap(err, "token unauthorized")
	}
	glg.Debugf("set roletoken result. tok: %s, act: %s, res: %s", tok, act, res)
	a.cache.SetWithExpire(tok+act+res, struct{}{}, a.cacheExp)
	return nil
}

func (a *authorizer) VerifyRoleCert(ctx context.Context, peerCerts []*x509.Certificate, act, res string) error {
	dr := make([]string, 0, 2)
	drcheck := make(map[string]struct{})
	domainRoles := make(map[string][]string)
	for _, cert := range peerCerts {
		for _, uri := range cert.URIs {
			if strings.HasPrefix(uri.String(), a.roleCertURIPrefix) {
				dr = strings.SplitN(strings.TrimPrefix(uri.String(), a.roleCertURIPrefix), "/", 2) // domain/role
				if len(dr) != 2 {
					continue
				}
				domain, roleName := dr[0], dr[1]
				// duplicated role check
				if _, ok := drcheck[domain+roleName]; !ok {
					domainRoles[domain] = append(domainRoles[domain], roleName)
					drcheck[domain+roleName] = struct{}{}
				}
			}
		}
	}

	if len(domainRoles) == 0 {
		return errors.New("invalid role certificate")
	}

	var err error
	for domain, roles := range domainRoles {
		// TODO futurework
		if err = a.policyd.CheckPolicy(ctx, domain, roles, act, res); err == nil {
			return nil
		}
	}

	return errors.Wrap(err, "role certificates unauthorized")
}

func (a *authorizer) GetPolicyCache(ctx context.Context) map[string]interface{} {
	return a.policyd.GetPolicyCache(ctx)

}
