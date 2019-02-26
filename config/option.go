package config

import (
	"net/http"
	"time"

	"github.com/pkg/errors"
)

var (
	defaultOptions = []Option{
		SysAuthDomain("sys.auth"),
		ETagExpTime("168h"), // 1 week
		ETagFlushDur("168h"),
		RefreshDuration("24h"),
		HttpClient(&http.Client{}),
	}
)

type Option func(*confd) error

func AthenzURL(url string) Option {
	return func(c *confd) error {
		if url == "" {
			return nil
		}
		c.athenzURL = regex.ReplaceAllString(url, "")
		return nil
	}
}

func SysAuthDomain(d string) Option {
	return func(c *confd) error {
		if d == "" {
			return nil
		}
		c.sysAuthDomain = d
		return nil
	}
}

func ETagExpTime(t string) Option {
	return func(c *confd) error {
		if t == "" {
			return nil
		}
		if etagExpTime, err := time.ParseDuration(t); err != nil {
			return errors.Wrap(err, "invalid etag expire time")
		} else {
			c.etagExpTime = etagExpTime
			return nil
		}
	}
}

func ETagFlushDur(t string) Option {
	return func(c *confd) error {
		if t == "" {
			return nil
		}
		if etagFlushDur, err := time.ParseDuration(t); err != nil {
			return errors.Wrap(err, "invalid etag flush duration")
		} else {
			c.etagFlushDur = etagFlushDur
			return nil
		}
	}
}

func RefreshDuration(t string) Option {
	return func(c *confd) error {
		if t == "" {
			return nil
		}
		if rd, err := time.ParseDuration(t); err != nil {
			return errors.Wrap(err, "invalid refresh druation")
		} else {
			c.refreshDuration = rd
			return nil
		}
	}
}

func HttpClient(cl *http.Client) Option {
	return func(c *confd) error {
		if c != nil {
			c.client = cl
		}
		return nil
	}
}
