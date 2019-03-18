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
package providerd

import (
	"net/http"
	"time"

	"github.com/kpango/gache"
)

var (
	defaultOptions = []Option{
		AthenzURL("www.athenz.com/zts/v1"),
		Transport(nil),
		Cache(gache.New(), time.Minute),
	}
)

// Option represents a functional options pattern interface
type Option func(*provider) error

// PolicyRefreshDuration represents a PolicyRefreshDuration functional option
func PolicyRefreshDuration(t string) Option {
	return func(prov *provider) error {
		prov.policyRefreshDuration = t
		return nil
	}
}

// AthenzConfRefreshDuration represents a AthenzConfRefreshDuration functional option
func AthenzConfRefreshDuration(t string) Option {
	return func(prov *provider) error {
		prov.athenzConfRefreshDuration = t
		return nil
	}
}

// AthenzURL represents a AthenzURL functional option
func AthenzURL(url string) Option {
	return func(prov *provider) error {
		prov.athenzURL = url
		return nil
	}
}

// AthenzDomains represents a AthenzDomains functional option
func AthenzDomains(domains []string) Option {
	return func(prov *provider) error {
		prov.athenzDomains = domains
		return nil
	}
}

// athenzConfd parameters

// AthenzConfSysAuthDomain represents a AthenzConfSysAuthDomain functional option
func AthenzConfSysAuthDomain(domain string) Option {
	return func(prov *provider) error {
		prov.athenzConfSysAuthDomain = domain
		return nil
	}
}

// AthenzConfEtagExpTime represents a AthenzConfEtagExpTime functional option
func AthenzConfEtagExpTime(t string) Option {
	return func(prov *provider) error {
		prov.athenzConfEtagExpTime = t
		return nil
	}
}

// AthenzConfEtagFlushDur represents a AthenzConfEtagFlushDur functional option
func AthenzConfEtagFlushDur(t string) Option {
	return func(prov *provider) error {
		prov.athenzConfEtagFlushDur = t
		return nil
	}
}

// policyd parameters

// PolicyExpireMargin represents a PolicyExpireMargin functional option
func PolicyExpireMargin(t string) Option {
	return func(prov *provider) error {
		prov.policyExpireMargin = t
		return nil
	}
}

// PolicyEtagFlushDur represents a PolicyEtagFlushDur functional option
func PolicyEtagFlushDur(t string) Option {
	return func(prov *provider) error {
		prov.policyEtagFlushDur = t
		return nil
	}
}

// PolicyEtagExpTime represents a PolicyEtagExpTime functional option
func PolicyEtagExpTime(t string) Option {
	return func(prov *provider) error {
		prov.policyEtagExpTime = t
		return nil
	}
}

// Transport represents a Transport functional option
func Transport(t *http.Transport) Option {
	return func(prov *provider) error {
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

// Cache represents a Cache functional option
func Cache(c gache.Gache, dur time.Duration) Option {
	return func(prov *provider) error {
		prov.cache = c.SetDefaultExpire(dur)
		prov.cacheExp = dur
		return nil
	}
}
