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

// Option represents a functional options pattern interface
type Option func(*authorizer) error

// WithAthenzURL represents a AthenzURL functional option
func WithAthenzURL(url string) Option {
	return func(prov *authorizer) error {
		prov.athenzURL = url
		return nil
	}
}

// WithAthenzDomains represents a AthenzDomains functional option
func WithAthenzDomains(domains ...string) Option {
	return func(prov *authorizer) error {
		prov.athenzDomains = domains
		return nil
	}
}

// WithTransport represents a Transport functional option
func WithTransport(t *http.Transport) Option {
	return func(prov *authorizer) error {
		if t == nil {
			prov.client = &http.Client{
				Timeout: time.Second * 30,
			}
			return nil
		}
		prov.client = &http.Client{
			Transport: t,
		}
		return nil
	}
}

// WithCacheExp represents the cache expiration time
func WithCacheExp(exp time.Duration) Option {
	return func(prov *authorizer) error {
		prov.cache.SetDefaultExpire(exp)
		prov.cacheExp = exp
		return nil
	}
}

// WithRoleCertURIPrefix represents a RoleCertURIPrefix functional option
func WithRoleCertURIPrefix(t string) Option {
	return func(prov *authorizer) error {
		prov.roleCertURIPrefix = t
		return nil
	}
}

/*
	Pubkeyd parameters
*/

// WithEnablePubkeyd represents a EnablePubkey functional optiond
func WithEnablePubkeyd() Option {
	return func(prov *authorizer) error {
		prov.disablePubkeyd = false
		return nil
	}
}

// WithDisablePubkeyd represents a DisablePubkey functional optiond
func WithDisablePubkeyd() Option {
	return func(prov *authorizer) error {
		prov.disablePubkeyd = true
		return nil
	}
}

// WithPubkeyRefreshDuration represents a PubkeyRefreshDuration functional option
func WithPubkeyRefreshDuration(t string) Option {
	return func(prov *authorizer) error {
		prov.pubkeyRefreshDuration = t
		return nil
	}
}

// WithPubkeyErrRetryInterval represents a PubkeyErrRetryInterval functional option
func WithPubkeyErrRetryInterval(i string) Option {
	return func(prov *authorizer) error {
		prov.pubkeyErrRetryInterval = i
		return nil
	}
}

// WithPubkeySysAuthDomain represents a PubkeySysAuthDomain functional option
func WithPubkeySysAuthDomain(domain string) Option {
	return func(prov *authorizer) error {
		prov.pubkeySysAuthDomain = domain
		return nil
	}
}

// WithPubkeyEtagExpTime represents a PubkeyEtagExpTime functional option
func WithPubkeyEtagExpTime(t string) Option {
	return func(prov *authorizer) error {
		prov.pubkeyEtagExpTime = t
		return nil
	}
}

// WithPubkeyEtagFlushDuration represents a PubkeyEtagFlushDur functional option
func WithPubkeyEtagFlushDuration(t string) Option {
	return func(prov *authorizer) error {
		prov.pubkeyEtagFlushDur = t
		return nil
	}
}

/*
	policyd parameters
*/

// WithEnablePolicyd represents a EnablePolicyd functional optiond
func WithEnablePolicyd() Option {
	return func(prov *authorizer) error {
		prov.disablePolicyd = false
		return nil
	}
}

// WithDisablePolicyd represents a DisablePolicyd functional optiond
func WithDisablePolicyd() Option {
	return func(prov *authorizer) error {
		prov.disablePolicyd = true
		return nil
	}
}

// WithPolicyRefreshDuration represents a PolicyRefreshDuration functional option
func WithPolicyRefreshDuration(t string) Option {
	return func(prov *authorizer) error {
		prov.policyRefreshDuration = t
		return nil
	}
}

// WithPolicyErrRetryInterval represents a PolicyErrRetryInterval functional option
func WithPolicyErrRetryInterval(i string) Option {
	return func(prov *authorizer) error {
		prov.policyErrRetryInterval = i
		return nil
	}
}

// WithPolicyExpireMargin represents a PolicyExpireMargin functional option
func WithPolicyExpireMargin(t string) Option {
	return func(prov *authorizer) error {
		prov.policyExpireMargin = t
		return nil
	}
}

// WithPolicyEtagExpTime represents a PolicyEtagExpTime functional option
func WithPolicyEtagExpTime(t string) Option {
	return func(prov *authorizer) error {
		prov.policyEtagExpTime = t
		return nil
	}
}

// WithPolicyEtagFlushDuration represents a PolicyEtagFlushDur functional option
func WithPolicyEtagFlushDuration(t string) Option {
	return func(prov *authorizer) error {
		prov.policyEtagFlushDur = t
		return nil
	}
}

/*
	jwkd parameters
*/

// WithEnableJwkd represents a EnableJwkd functional optiond
func WithEnableJwkd() Option {
	return func(prov *authorizer) error {
		prov.disableJwkd = false
		return nil
	}
}

// WithDisableJwkd represents a DisableJwkd functional optiond
func WithDisableJwkd() Option {
	return func(prov *authorizer) error {
		prov.disableJwkd = true
		return nil
	}
}

// WithJwkRefreshDuration represents a JwkRefreshDuration functional option
func WithJwkRefreshDuration(t string) Option {
	return func(prov *authorizer) error {
		prov.jwkRefreshDuration = t
		return nil
	}
}

// WithJwkErrRetryInterval represents a JwkErrRetryInterval functional option
func WithJwkErrRetryInterval(i string) Option {
	return func(prov *authorizer) error {
		prov.jwkErrRetryInterval = i
		return nil
	}
}
