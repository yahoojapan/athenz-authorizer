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
	"net/http"
	"time"

	urlutil "github.com/yahoojapan/athenz-authorizer/v4/internal/url"
)

const (
	defaultHTTPClientTimeout = 30
)

var (
	defaultOptions = []Option{
		WithAthenzURL("athenz.io/zts/v1"),
		WithHTTPClient(nil),
		WithCacheExp(time.Minute),
		WithEnablePubkeyd(),
		WithEnablePolicyd(),
		WithEnableJwkd(),
		WithAccessTokenParam(NewAccessTokenParam(true, true, "1h", "1h", false, nil)),
		WithEnableRoleToken(),
		WithRoleAuthHeader("Athenz-Role-Auth"),
		WithEnableRoleCert(),
		WithRoleCertURIPrefix("athenz://role/"),
	}
)

type AccessTokenParam struct {
	enable               bool
	verifyCertThumbprint bool
	certBackdateDur      string
	certOffsetDur        string
	verifyClientID       bool
	authorizedClientIDs  map[string][]string
}

// Option represents a functional option
type Option func(*authority) error

// WithAthenzURL returns an AthenzURL functional option
func WithAthenzURL(url string) Option {
	return func(authz *authority) error {
		u := urlutil.TrimHTTPScheme(url)
		if urlutil.HasScheme(u) {
			return urlutil.ErrUnsupportedScheme
		}
		authz.athenzURL = u
		return nil
	}
}

// WithAthenzDomains returns an AthenzDomains functional option
func WithAthenzDomains(domains ...string) Option {
	return func(authz *authority) error {
		authz.athenzDomains = domains
		return nil
	}
}

// WithHTTPClient returns a HTTPClient functional option
func WithHTTPClient(c *http.Client) Option {
	return func(authz *authority) error {
		if c == nil {
			authz.client = &http.Client{
				Timeout: defaultHTTPClientTimeout * time.Second,
			}
			return nil
		}
		authz.client = c
		return nil
	}
}

// WithCacheExp returns a CacheExp functional option
func WithCacheExp(exp time.Duration) Option {
	return func(authz *authority) error {
		authz.cache.SetDefaultExpire(exp)
		authz.cacheExp = exp
		return nil
	}
}

/*
	pubkeyd parameters
*/

// WithEnablePubkeyd returns an EnablePubkeyd functional option
func WithEnablePubkeyd() Option {
	return func(authz *authority) error {
		authz.disablePubkeyd = false
		return nil
	}
}

// WithDisablePubkeyd returns a DisablePubkeyd functional option
func WithDisablePubkeyd() Option {
	return func(authz *authority) error {
		authz.disablePubkeyd = true
		return nil
	}
}

// WithPubkeyRefreshPeriod returns a PubkeyRefreshPeriod functional option
func WithPubkeyRefreshPeriod(t string) Option {
	return func(authz *authority) error {
		authz.pubkeyRefreshPeriod = t
		return nil
	}
}

// WithPubkeyRetryDelay returns a PubkeyRetryDelay functional option
func WithPubkeyRetryDelay(i string) Option {
	return func(authz *authority) error {
		authz.pubkeyRetryDelay = i
		return nil
	}
}

// WithPubkeySysAuthDomain returns a PubkeySysAuthDomain functional option
func WithPubkeySysAuthDomain(domain string) Option {
	return func(authz *authority) error {
		authz.pubkeySysAuthDomain = domain
		return nil
	}
}

// WithPubkeyETagExpiry returns a PubkeyETagExpiry functional option
func WithPubkeyETagExpiry(t string) Option {
	return func(authz *authority) error {
		authz.pubkeyETagExpiry = t
		return nil
	}
}

// WithPubkeyETagPurgePeriod returns a PubkeyETagPurgePeriod functional option
func WithPubkeyETagPurgePeriod(t string) Option {
	return func(authz *authority) error {
		authz.pubkeyETagPurgePeriod = t
		return nil
	}
}

/*
	policyd parameters
*/

// WithEnablePolicyd returns an EnablePolicyd functional option
func WithEnablePolicyd() Option {
	return func(authz *authority) error {
		authz.disablePolicyd = false
		return nil
	}
}

// WithDisablePolicyd returns a DisablePolicyd functional option
func WithDisablePolicyd() Option {
	return func(authz *authority) error {
		authz.disablePolicyd = true
		return nil
	}
}

// WithPolicyRefreshPeriod returns a PolicyRefreshPeriod functional option
func WithPolicyRefreshPeriod(t string) Option {
	return func(authz *authority) error {
		authz.policyRefreshPeriod = t
		return nil
	}
}

// WithPolicyExpiryMargin returns a PolicyExpiryMargin functional option
func WithPolicyExpiryMargin(t string) Option {
	return func(authz *authority) error {
		authz.policyExpiryMargin = t
		return nil
	}
}

// WithPolicyPurgePeriod returns a PolicyPurgePeriod functional option
func WithPolicyPurgePeriod(t string) Option {
	return func(authz *authority) error {
		authz.policyPurgePeriod = t
		return nil
	}
}

// WithPolicyRetryDelay returns a PolicyRetryDelay functional option
func WithPolicyRetryDelay(i string) Option {
	return func(authz *authority) error {
		authz.policyRetryDelay = i
		return nil
	}
}

// WithPolicyRetryAttempts returns a PolicyRetryAttempts functional option
func WithPolicyRetryAttempts(c int) Option {
	return func(authz *authority) error {
		authz.policyRetryAttempts = c
		return nil
	}
}

/*
	jwkd parameters
*/

// WithEnableJwkd returns an EnableJwkd functional option
func WithEnableJwkd() Option {
	return func(authz *authority) error {
		authz.disableJwkd = false
		return nil
	}
}

// WithDisableJwkd returns a DisableJwkd functional option
func WithDisableJwkd() Option {
	return func(authz *authority) error {
		authz.disableJwkd = true
		return nil
	}
}

// WithJwkRefreshPeriod returns a JwkRefreshPeriod functional option
func WithJwkRefreshPeriod(t string) Option {
	return func(authz *authority) error {
		authz.jwkRefreshPeriod = t
		return nil
	}
}

// WithJwkRetryDelay returns a JwkRetryDelay functional option
func WithJwkRetryDelay(i string) Option {
	return func(authz *authority) error {
		authz.jwkRetryDelay = i
		return nil
	}
}

// WithJwkURLs returns a JwkURLs functional option
func WithJwkURLs(urls []string) Option {
	return func(authz *authority) error {
		authz.jwkURLs = urls
		return nil
	}
}

/*
	access token parameters
*/

// NewAccessTokenParam returns a new access token parameter
func NewAccessTokenParam(enable bool, verifyCertThumbprint bool, certBackdateDur, certOffsetDur string, verifyClientID bool, authorizedClientIDs map[string][]string) AccessTokenParam {
	return AccessTokenParam{
		// Flag to enable verify of access token
		enable: enable,
		// The client certificate Thumbprint hash and access token cnf checks are enabled. (Certificate-Bound Access Tokens)
		verifyCertThumbprint: verifyCertThumbprint,
		// If the time of issuance of the certificate is intentionally earlier, specify that time.
		certBackdateDur: certBackdateDur,
		// If the certificate and token have not been bound, specify the time to determine that the certificate has been updated.
		certOffsetDur: certOffsetDur,
		// The client certificate common name and client_id verification.
		verifyClientID: verifyClientID,
		// The list of authorized client_id and common name.
		authorizedClientIDs: authorizedClientIDs,
	}
}

// WithAccessTokenParam returns a functional option that new access token parameter
func WithAccessTokenParam(accessTokenParam AccessTokenParam) Option {
	return func(authz *authority) error {
		authz.accessTokenParam = accessTokenParam
		return nil
	}
}

/*
	role token parameters
*/

// WithEnableRoleToken returns a enable roletoken functional option
func WithEnableRoleToken() Option {
	return func(authz *authority) error {
		authz.enableRoleToken = true
		return nil
	}
}

// WithDisableRoleToken returns a disable roletoken functional option
func WithDisableRoleToken() Option {
	return func(authz *authority) error {
		authz.enableRoleToken = false
		return nil
	}
}

// WithRoleAuthHeader returns a RoleAuthHeader functional option
func WithRoleAuthHeader(h string) Option {
	return func(authz *authority) error {
		authz.roleAuthHeader = h
		return nil
	}
}

/*
	role certificate parameters
*/

// WithEnableRoleCert returns a enable rolecert functional option
func WithEnableRoleCert() Option {
	return func(authz *authority) error {
		authz.enableRoleCert = true
		return nil
	}
}

// WithDisableRoleCert returns a disable rolecert functional option
func WithDisableRoleCert() Option {
	return func(authz *authority) error {
		authz.enableRoleCert = false
		return nil
	}
}

// WithRoleCertURIPrefix returns a RoleCertURIPrefix functional option
func WithRoleCertURIPrefix(t string) Option {
	return func(authz *authority) error {
		authz.roleCertURIPrefix = t
		return nil
	}
}
