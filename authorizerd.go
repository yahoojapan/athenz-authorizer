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

	"github.com/dgrijalva/jwt-go/request"
	"github.com/kpango/gache"
	"github.com/kpango/glg"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	"github.com/yahoojapan/athenz-authorizer/v4/access"
	"github.com/yahoojapan/athenz-authorizer/v4/jwk"
	"github.com/yahoojapan/athenz-authorizer/v4/policy"
	"github.com/yahoojapan/athenz-authorizer/v4/pubkey"
	"github.com/yahoojapan/athenz-authorizer/v4/role"
)

// Authorizerd represents a daemon for user to verify the role token
type Authorizerd interface {
	Init(ctx context.Context) error
	Start(ctx context.Context) <-chan error
	Verify(r *http.Request, act, res string) error
	VerifyAccessToken(ctx context.Context, tok, act, res string, cert *x509.Certificate) error
	VerifyRoleToken(ctx context.Context, tok, act, res string) error
	VerifyRoleCert(ctx context.Context, peerCerts []*x509.Certificate, act, res string) error
	GetPolicyCache(ctx context.Context) map[string]interface{}
}

type verifier func(r *http.Request, act, res string) error

type authorizer struct {
	//
	pubkeyd         pubkey.Daemon
	policyd         policy.Daemon
	jwkd            jwk.Daemon
	roleProcessor   role.Processor
	accessProcessor access.Processor
	verifiers       []verifier

	// athenz connection parameters
	athenzURL string
	client    *http.Client

	// successful result cache
	cache    gache.Gache
	cacheExp time.Duration

	// roleCertURIPrefix
	roleCertURIPrefix string

	// pubkeyd parameters
	disablePubkeyd        bool
	pubkeyRefreshPeriod   string
	pubkeyRetryDelay      string
	pubkeySysAuthDomain   string
	pubkeyETagExpiry      string
	pubkeyETagPurgePeriod string

	// policyd parameters
	disablePolicyd      bool
	athenzDomains       []string
	policyExpiryMargin  string
	policyRefreshPeriod string
	policyPurgePeriod   string
	policyRetryDelay    string
	policyRetryAttempts int

	// jwkd parameters
	disableJwkd      bool
	jwkRefreshPeriod string
	jwkRetryDelay    string

	// accessTokenProcessor parameters
	accessTokenParam AccessTokenParam

	// roleTokenProcessor parameters
	enableRoleToken bool
	roleAuthHeader  string

	// roleCertificateProcessor parameters
	enableRoleCert bool
}

type mode uint8

const (
	roleToken mode = iota
	accessToken
)

// New creates the Authorizerd object with the options
func New(opts ...Option) (Authorizerd, error) {
	var (
		prov = &authorizer{
			cache: gache.New(),
		}
		err    error
		pkPro  pubkey.Provider
		jwkPro jwk.Provider
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
			pubkey.WithETagExpiry(prov.pubkeyETagExpiry),
			pubkey.WithETagPurgePeriod(prov.pubkeyETagPurgePeriod),
			pubkey.WithRefreshPeriod(prov.pubkeyRefreshPeriod),
			pubkey.WithRetryDelay(prov.pubkeyRetryDelay),
			pubkey.WithHTTPClient(prov.client),
		); err != nil {
			return nil, err
		}
		pkPro = prov.pubkeyd.GetProvider()
	}

	if !prov.disablePolicyd {
		if prov.policyd, err = policy.New(
			policy.WithAthenzURL(prov.athenzURL),
			policy.WithAthenzDomains(prov.athenzDomains...),
			policy.WithExpiryMargin(prov.policyExpiryMargin),
			policy.WithRefreshPeriod(prov.policyRefreshPeriod),
			policy.WithPurgePeriod(prov.policyPurgePeriod),
			policy.WithRetryDelay(prov.policyRetryDelay),
			policy.WithRetryAttempts(prov.policyRetryAttempts),
			policy.WithHTTPClient(prov.client),
			policy.WithPubKeyProvider(pkPro),
		); err != nil {
			return nil, err
		}
	}

	if !prov.disableJwkd {
		if prov.jwkd, err = jwk.New(
			jwk.WithAthenzURL(prov.athenzURL),
			jwk.WithRefreshPeriod(prov.jwkRefreshPeriod),
			jwk.WithRetryDelay(prov.jwkRetryDelay),
			jwk.WithHTTPClient(prov.client),
		); err != nil {
			return nil, err
		}
		jwkPro = prov.jwkd.GetProvider()
	}

	if prov.enableRoleToken {
		if prov.roleProcessor, err = role.New(
			role.WithPubkeyProvider(pkPro),
			role.WithJWKProvider(jwkPro),
		); err != nil {
			return nil, err
		}
	}

	if prov.accessTokenParam.enable {
		if prov.accessProcessor, err = access.New(
			access.WithJWKProvider(jwkPro),
			access.WithEnableMTLSCertificateBoundAccessToken(prov.accessTokenParam.verifyCertThumbprint),
			access.WithEnableVerifyClientID(prov.accessTokenParam.verifyClientID),
			access.WithAuthorizedClientIDs(prov.accessTokenParam.authorizedClientIDs),
			access.WithClientCertificateGoBackSeconds(prov.accessTokenParam.certBackdateDur),
			access.WithClientCertificateOffsetSeconds(prov.accessTokenParam.certOffsetDur),
		); err != nil {
			return nil, err
		}
	}

	// create verifiers
	if err = prov.initVerifiers(); err != nil {
		return nil, errors.Wrap(err, "error create verifiers")
	}

	return prov, nil
}

func (a *authorizer) initVerifiers() error {
	// TODO: check empty credentials to speed up the checking
	verifiers := make([]verifier, 0, 3) // rolecert, access token, roletoken

	if a.enableRoleCert {
		rcVerifier := func(r *http.Request, act, res string) error {
			if r.TLS != nil {
				return a.VerifyRoleCert(r.Context(), r.TLS.PeerCertificates, act, res)
			}
			return a.VerifyRoleCert(r.Context(), nil, act, res)
		}
		glg.Info("initVerifiers: added role certificate verifier")
		verifiers = append(verifiers, rcVerifier)
	}

	if a.accessTokenParam.enable {
		atVerifier := func(r *http.Request, act, res string) error {
			tokenString, err := request.AuthorizationHeaderExtractor.ExtractToken(r)
			if err != nil {
				return err
			}
			if r.TLS != nil && len(r.TLS.PeerCertificates) != 0 {
				return a.VerifyAccessToken(r.Context(), tokenString, act, res, r.TLS.PeerCertificates[0])
			}
			return a.VerifyAccessToken(r.Context(), tokenString, act, res, nil)
		}
		glg.Infof("initVerifiers: added access token verifier having param: %+v", a.accessTokenParam)
		verifiers = append(verifiers, atVerifier)
	}

	if a.enableRoleToken {
		rtVerifier := func(r *http.Request, act, res string) error {
			return a.VerifyRoleToken(r.Context(), r.Header.Get(a.roleAuthHeader), act, res)
		}
		glg.Info("initVerifiers: added role token verifier")
		verifiers = append(verifiers, rtVerifier)
	}

	if len(verifiers) < 1 {
		return errors.New("error no verifiers")
	}

	// resize
	a.verifiers = make([]verifier, len(verifiers))
	copy(a.verifiers[0:], verifiers)
	return nil
}

// Init initializes child daemons synchronously.
func (a *authorizer) Init(ctx context.Context) error {
	eg, egCtx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		select {
		case <-egCtx.Done():
			return egCtx.Err()
		default:
			if !a.disablePubkeyd {
				err := a.pubkeyd.Update(egCtx)
				if err != nil {
					return err
				}
			}
			if !a.disablePolicyd {
				return a.policyd.Update(egCtx)
			}
			return nil
		}
	})
	if !a.disableJwkd {
		eg.Go(func() error {
			select {
			case <-egCtx.Done():
				return egCtx.Err()
			default:
				return a.jwkd.Update(egCtx)
			}
		})
	}

	return eg.Wait()
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
		defer close(ech)
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
	return a.verify(ctx, roleToken, tok, act, res, nil)
}

// VerifyAccessToken verifies the access token on the specific (action, resource) pair and returns verification error if unauthorized.
func (a *authorizer) VerifyAccessToken(ctx context.Context, tok, act, res string, cert *x509.Certificate) error {
	return a.verify(ctx, accessToken, tok, act, res, cert)
}

func (a *authorizer) verify(ctx context.Context, m mode, tok, act, res string, cert *x509.Certificate) error {
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
	case roleToken:
		rt, err := a.roleProcessor.ParseAndValidateRoleToken(tok)
		if err != nil {
			glg.Debugf("error parse and validate role token, err: %v", err)
			return errors.Wrap(err, "error verify role token")
		}
		domain = rt.Domain
		roles = rt.Roles
	case accessToken:
		ac, err := a.accessProcessor.ParseAndValidateOAuth2AccessToken(tok, cert)
		if err != nil {
			glg.Debugf("error parse and validate access token, err: %v", err)
			return errors.Wrap(err, "error verify access token")
		}
		domain = ac.Audience
		roles = ac.Scope
	}

	if err := a.policyd.CheckPolicy(ctx, domain, roles, act, res); err != nil {
		glg.Debugf("error check, err: %v", err)
		return errors.Wrap(err, "token unauthorized")
	}
	glg.Debugf("set roletoken result. tok: %s, act: %s, res: %s", tok, act, res)
	a.cache.SetWithExpire(tok+act+res, struct{}{}, a.cacheExp)
	return nil
}

// Verify returns error of verification. Returns nil if ANY verifier succeeds (OR logic).
func (a *authorizer) Verify(r *http.Request, act, res string) error {
	for _, verifier := range a.verifiers {
		// OR logic on multiple credentials
		err := verifier(r, act, res)
		if err == nil {
			return nil
		}
	}

	return ErrInvalidCredentials
}

// VerifyRoleCert verifies the role certificate for specific resource and return and verification error.
func (a *authorizer) VerifyRoleCert(ctx context.Context, peerCerts []*x509.Certificate, act, res string) error {
	var dr []string
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

// GetPolicyCache returns the cached policy data
func (a *authorizer) GetPolicyCache(ctx context.Context) map[string]interface{} {
	return a.policyd.GetPolicyCache(ctx)
}
