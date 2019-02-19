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

func PolicyRefreshDuration(t string) Option {
	return func(prov *provider) error {
		prov.policyRefreshDuration = t
		return nil
	}
}

func AthenzConfRefreshDuration(t string) Option {
	return func(prov *provider) error {
		prov.athenzConfRefreshDuration = t
		return nil
	}
}

func AthenzURL(url string) Option {
	return func(prov *provider) error {
		prov.athenzURL = url
		return nil
	}
}

func AthenzDomains(domains []string) Option {
	return func(prov *provider) error {
		prov.athenzDomains = domains
		return nil
	}
}

// athenzConfd parameters
func AthenzConfSysAuthDomain(domain string) Option {
	return func(prov *provider) error {
		prov.athenzConfSysAuthDomain = domain
		return nil
	}
}

func AthenzConfEtagExpTime(t string) Option {
	return func(prov *provider) error {
		prov.athenzConfEtagExpTime = t
		return nil
	}
}

func AthenzConfEtagFlushDur(t string) Option {
	return func(prov *provider) error {
		prov.athenzConfEtagFlushDur = t
		return nil
	}
}

// policyd parameters
func PolicyExpireMargin(t string) Option {
	return func(prov *provider) error {
		prov.policyExpireMargin = t
		return nil
	}
}

func PolicyEtagFlushDur(t string) Option {
	return func(prov *provider) error {
		prov.policyEtagFlushDur = t
		return nil
	}
}

func PolicyEtagExpTime(t string) Option {
	return func(prov *provider) error {
		prov.policyEtagExpTime = t
		return nil
	}
}

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

func Cache(c gache.Gache, dur time.Duration) Option {
	return func(prov *provider) error {
		prov.cache = c.SetDefaultExpire(dur)
		prov.cacheExp = dur
		return nil
	}
}
