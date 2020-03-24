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

	urlutil "github.com/yahoojapan/athenz-authorizer/v2/internal/url"
)

var (
	defaultOptions = []Option{
		WithAthenzURL("www.athenz.com/zts/v1"),
		WithTransport(nil),
		WithCacheExp(time.Minute),
		WithRoleCertURIPrefix("athenz://role/"),
		WithEnablePubkeyd(),
		WithEnablePolicyd(),
		WithEnableJwkd(),
		WithPolicyErrRetryInterval("1m"),
		WithPubkeyErrRetryInterval("1m"),
		WithJwkErrRetryInterval("1m"),
	}
)

// Option represents a functional option
type Option func(*authorizer) error

// WithAthenzURL returns an AthenzURL functional option
func WithAthenzURL(url string) Option {
	return func(authz *authorizer) error {
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
	return func(authz *authorizer) error {
		authz.athenzDomains = domains
		return nil
	}
}

// WithTransport returns a Transport functional option
func WithTransport(t *http.Transport) Option {
	return func(authz *authorizer) error {
		if t == nil {
			authz.client = &http.Client{
				Timeout: time.Second * 30,
			}
			return nil
		}
		authz.client = &http.Client{
			Transport: t,
		}
		return nil
	}
}

// WithCacheExp returns a CacheExp functional option
func WithCacheExp(exp time.Duration) Option {
	return func(authz *authorizer) error {
		authz.cache.SetDefaultExpire(exp)
		authz.cacheExp = exp
		return nil
	}
}

// WithRoleCertURIPrefix returns a RoleCertURIPrefix functional option
func WithRoleCertURIPrefix(t string) Option {
	return func(authz *authorizer) error {
		authz.roleCertURIPrefix = t
		return nil
	}
}

/*
	pubkeyd parameters
*/

// WithEnablePubkeyd returns an EnablePubkey functional option
func WithEnablePubkeyd() Option {
	return func(authz *authorizer) error {
		authz.disablePubkeyd = false
		return nil
	}
}

// WithDisablePubkeyd returns a DisablePubkey functional option
func WithDisablePubkeyd() Option {
	return func(authz *authorizer) error {
		authz.disablePubkeyd = true
		return nil
	}
}

// WithPubkeyRefreshDuration returns a PubkeyRefreshDuration functional option
func WithPubkeyRefreshDuration(t string) Option {
	return func(authz *authorizer) error {
		authz.pubkeyRefreshDuration = t
		return nil
	}
}

// WithPubkeyErrRetryInterval returns a PubkeyErrRetryInterval functional option
func WithPubkeyErrRetryInterval(i string) Option {
	return func(authz *authorizer) error {
		authz.pubkeyErrRetryInterval = i
		return nil
	}
}

// WithPubkeySysAuthDomain returns a PubkeySysAuthDomain functional option
func WithPubkeySysAuthDomain(domain string) Option {
	return func(authz *authorizer) error {
		authz.pubkeySysAuthDomain = domain
		return nil
	}
}

// WithPubkeyEtagExpTime returns a PubkeyEtagExpTime functional option
func WithPubkeyEtagExpTime(t string) Option {
	return func(authz *authorizer) error {
		authz.pubkeyEtagExpTime = t
		return nil
	}
}

// WithPubkeyEtagFlushDuration returns a PubkeyEtagFlushDur functional option
func WithPubkeyEtagFlushDuration(t string) Option {
	return func(authz *authorizer) error {
		authz.pubkeyEtagFlushDur = t
		return nil
	}
}

/*
	policyd parameters
*/

// WithEnablePolicyd returns an EnablePolicyd functional option
func WithEnablePolicyd() Option {
	return func(authz *authorizer) error {
		authz.disablePolicyd = false
		return nil
	}
}

// WithDisablePolicyd returns a DisablePolicyd functional option
func WithDisablePolicyd() Option {
	return func(authz *authorizer) error {
		authz.disablePolicyd = true
		return nil
	}
}

// WithPolicyRefreshDuration returns a PolicyRefreshDuration functional option
func WithPolicyRefreshDuration(t string) Option {
	return func(authz *authorizer) error {
		authz.policyRefreshDuration = t
		return nil
	}
}

// WithPolicyErrRetryInterval returns a PolicyErrRetryInterval functional option
func WithPolicyErrRetryInterval(i string) Option {
	return func(authz *authorizer) error {
		authz.policyErrRetryInterval = i
		return nil
	}
}

// WithPolicyExpireMargin returns a PolicyExpireMargin functional option
func WithPolicyExpireMargin(t string) Option {
	return func(authz *authorizer) error {
		authz.policyExpireMargin = t
		return nil
	}
}

/*
	jwkd parameters
*/

// WithEnableJwkd returns an EnableJwkd functional option
func WithEnableJwkd() Option {
	return func(authz *authorizer) error {
		authz.disableJwkd = false
		return nil
	}
}

// WithDisableJwkd returns a DisableJwkd functional option
func WithDisableJwkd() Option {
	return func(authz *authorizer) error {
		authz.disableJwkd = true
		return nil
	}
}

// WithJwkRefreshDuration returns a JwkRefreshDuration functional option
func WithJwkRefreshDuration(t string) Option {
	return func(authz *authorizer) error {
		authz.jwkRefreshDuration = t
		return nil
	}
}

// WithJwkErrRetryInterval returns a JwkErrRetryInterval functional option
func WithJwkErrRetryInterval(i string) Option {
	return func(authz *authorizer) error {
		authz.jwkErrRetryInterval = i
		return nil
	}
}

/*
	processor parameters
*/

// WithProcessorClientCertificateGoBackSeconds returns a ProcessorClientCertificateGoBackSeconds functional option
func WithProcessorClientCertificateGoBackSeconds(s int64) Option {
	return func(authz *authorizer) error {
		authz.processorClientCertificateGoBackSeconds = s
		return nil
	}
}

// WithProcessorClientCertificateOffsetSeconds returns a ProcessorClientCertificateOffsetSeconds functional option
func WithProcessorClientCertificateOffsetSeconds(s int64) Option {
	return func(authz *authorizer) error {
		authz.processorClientCertificateOffsetSeconds = s
		return nil
	}
}
