package policy

import (
	"net/http"
	"time"

	"github.com/yahoojapan/athenz-policy-updater/config"
	"github.com/pkg/errors"
)

var (
	defaultOptions = []Option{
		ExpireMargin("3h"),
		EtagFlushDur("24h"),
		EtagExpTime("24h"),
		RefreshDuration("30m"),
		HttpClient(&http.Client{}),
	}
)

// Option represents a functional options pattern interface
type Option func(*policy) error

func EtagFlushDur(t string) Option {
	return func(pol *policy) error {
		if t == "" {
			return nil
		}
		if etagFlushDur, err := time.ParseDuration(t); err != nil {
			return errors.Wrap(err, "invalid flush duration")
		} else {
			pol.etagFlushDur = etagFlushDur
			return nil
		}
	}
}

func ExpireMargin(t string) Option {
	return func(pol *policy) error {
		if t == "" {
			return nil
		}
		if expireMargin, err := time.ParseDuration(t); err != nil {
			return errors.Wrap(err, "invalid expire margin")
		} else {
			pol.expireMargin = expireMargin
			return nil
		}
	}
}

func EtagExpTime(t string) Option {
	return func(pol *policy) error {
		if t == "" {
			return nil
		}
		if etagExpTime, err := time.ParseDuration(t); err != nil {
			return errors.Wrap(err, "invalid etag expire time")
		} else {
			pol.etagExpTime = etagExpTime
			return nil
		}
	}
}

func AthenzURL(url string) Option {
	return func(pol *policy) error {
		if url == "" {
			return nil
		}
		pol.athenzURL = url
		return nil
	}
}

func AthenzDomains(doms []string) Option {
	return func(pol *policy) error {
		if doms == nil {
			return nil
		}
		pol.athenzDomains = doms
		return nil
	}
}

func RefreshDuration(t string) Option {
	return func(pol *policy) error {
		if t == "" {
			return nil
		}
		if rd, err := time.ParseDuration(t); err != nil {
			return errors.Wrap(err, "invalid refresh duration")
		} else {
			pol.refreshDuration = rd
			return nil
		}
	}
}

func HttpClient(c *http.Client) Option {
	return func(pol *policy) error {
		if c != nil {
			pol.client = c
		}
		return nil
	}
}

func PubKeyProvider(pkp config.PubKeyProvider) Option {
	return func(pol *policy) error {
		if pkp != nil {
			pol.pkp = pkp
		}
		return nil
	}
}
