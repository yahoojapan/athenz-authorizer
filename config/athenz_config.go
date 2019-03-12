package config

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/kpango/gache"
	"github.com/kpango/glg"
	authcore "github.com/yahoo/athenz/libs/go/zmssvctoken"
	"golang.org/x/sync/errgroup"
)

type AthenzConfd interface {
	StartConfUpdator(ctx context.Context) <-chan error
	UpdateAthenzConfig(context.Context) error
	GetPubKeyProvider() PubKeyProvider
}

type confd struct {
	athenzURL        string
	sysAuthDomain    string
	refreshDuration  time.Duration
	errRetryInterval time.Duration

	client *http.Client

	etagCache    gache.Gache
	etagExpTime  time.Duration
	etagFlushDur time.Duration

	// cache
	confCache *AthenzConfig
}

type AthenzConfig struct {
	ZMSPubKeys *sync.Map //map[string]authcore.Verifier
	ZTSPubKeys *sync.Map //map[string]authcore.Verifier
}

type confCache struct {
	eTag string
	sac  *SysAuthConfig
}

type PubKeyProvider func(AthenzEnv, string) authcore.Verifier

type AthenzEnv string

const (
	EnvZMS AthenzEnv = "zms"
	EnvZTS AthenzEnv = "zts"
)

var (
	regex = regexp.MustCompile("^(http|https)://")

	ErrFetchAthenzConf = errors.New("Fetch athenz config error")
	ErrEmptyAthenzConf = errors.New("Athenz config not initialized")
)

func NewAthenzConfd(opts ...Option) (AthenzConfd, error) {
	c := &confd{
		confCache: &AthenzConfig{
			ZMSPubKeys: new(sync.Map),
			ZTSPubKeys: new(sync.Map),
		},
		etagCache: gache.New(),
	}

	for _, opt := range append(defaultOptions, opts...) {
		if err := opt(c); err != nil {
			return nil, err
		}
	}

	return c, nil
}

func (c *confd) StartConfUpdator(ctx context.Context) <-chan error {
	glg.Info("Starting confd updator")
	ech := make(chan error, 100)
	fch := make(chan struct{}, 1)
	if err := c.UpdateAthenzConfig(ctx); err != nil {
		ech <- errors.Wrap(err, "error update athenz config")
		fch <- struct{}{}
	}

	go func() {
		defer close(fch)
		defer close(ech)
		c.etagCache.StartExpired(ctx, c.etagFlushDur)
		ticker := time.NewTicker(c.refreshDuration)
		var ebuf error
		for {
			select {
			case <-ctx.Done():
				glg.Info("Stopping confd updator")
				ticker.Stop()
				if ebuf != nil {
					ech <- errors.Wrap(ctx.Err(), ebuf.Error())
				} else {
					ech <- ctx.Err()
				}
				return
			case <-fch:
				if err := c.UpdateAthenzConfig(ctx); err != nil {
					err = errors.Wrap(err, "error update athenz config")
					select {
					case ech <- errors.Wrap(ebuf, err.Error()):
						ebuf = nil
					default:
						ebuf = errors.Wrap(ebuf, err.Error())
					}
					time.Sleep(c.errRetryInterval)
					select {
					case fch <- struct{}{}:
					default:
						glg.Warn("failure queue already full")
					}
				}
			case <-ticker.C:
				if err := c.UpdateAthenzConfig(ctx); err != nil {
					err = errors.Wrap(err, "error update athenz config")
					select {
					case ech <- errors.Wrap(ebuf, err.Error()):
						ebuf = nil
					default:
						ebuf = errors.Wrap(ebuf, err.Error())
					}
					select {
					case fch <- struct{}{}:
					default:
						glg.Warn("failure queue already full")
					}
				}
			}
		}
	}()

	return ech
}

func (c *confd) UpdateAthenzConfig(ctx context.Context) error {
	glg.Info("Updating athenz config")
	eg := errgroup.Group{}

	// this function decode and create verifier obj and store to corresponding cache map
	updConf := func(env AthenzEnv, cache *sync.Map) error {
		cm := new(sync.Map)
		dec := new(authcore.YBase64)
		pubKeys, upded, err := c.fetchPubKeyEntries(ctx, env)
		if err != nil {
			glg.Errorf("Error updating athenz config, error: %v", err)
			return errors.Wrap(err, "error fetch public key entries")
		}
		if !upded {
			glg.Infof("%v athenz config not updated", env)
			return nil
		}

		for _, key := range pubKeys.PublicKeys {
			glg.Debugf("Decoding key, keyID: %v", key.ID)
			decKey, err := dec.DecodeString(key.Key)
			if err != nil {
				glg.Errorf("error decoding key, error: %v", err)
				return errors.Wrap(err, "error decoding key")
			}
			ver, err := authcore.NewVerifier(decKey)
			if err != nil {
				glg.Errorf("error initializing verifier, error: %v", err)
				return errors.Wrap(err, "error initializing verifier")
			}
			cm.Store(key.ID, ver)
			glg.Debugf("Successfully decode key, keyID: %v", key.ID)
		}
		cm.Range(func(key interface{}, val interface{}) bool {
			cache.Store(key, val)
			return true
		})
		cache.Range(func(key interface{}, val interface{}) bool {
			_, ok := cm.Load(key)
			if !ok {
				cache.Delete(key)
			}
			return true
		})

		return nil
	}

	eg.Go(func() error {
		glg.Info("Updating ZTS athenz config")
		if err := updConf(EnvZTS, c.confCache.ZTSPubKeys); err != nil {
			return errors.Wrap(err, "Error updating ZTS athenz config")
		}
		glg.Info("Update ZTS athenz config success")
		return nil
	})

	eg.Go(func() error {
		glg.Info("Updating ZMS athenz config")
		if err := updConf(EnvZMS, c.confCache.ZMSPubKeys); err != nil {
			return errors.Wrap(err, "Error updating ZMS athenz config")
		}
		glg.Info("Update ZMS athenz config success")
		return nil
	})

	if err := eg.Wait(); err != nil {
		return errors.Wrap(err, "error when processing pub key")
	}

	return nil
}

func (c *confd) GetPubKeyProvider() PubKeyProvider {
	return c.getPubKey
}

func (c *confd) fetchPubKeyEntries(ctx context.Context, env AthenzEnv) (*SysAuthConfig, bool, error) {
	glg.Info("Fetching public key entries")
	// https://{www.athenz.com/zts/v1}/domain/sys.auth/service/zts
	url := fmt.Sprintf("https://%s/domain/%s/service/%s", c.athenzURL, c.sysAuthDomain, env)
	glg.Debugf("Fetching public key from %s", url)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		glg.Errorf("Fetch public key entries error: %v", err)
		return nil, false, errors.Wrap(err, "error creating getPub request")
	}

	// etag header
	t, ok := c.etagCache.Get(string(env))
	if ok {
		eTag := t.(*confCache).eTag
		glg.Debugf("ETag %v found in the cache", eTag)
		req.Header.Set("If-None-Match", eTag)
	}

	r, err := c.client.Do(req.WithContext(ctx))
	if err != nil {
		glg.Errorf("Error making HTTP request, error: %v", err)
		return nil, false, errors.Wrap(err, "error make http request")
	}

	// if server return NotModified, return policy from cache
	if r.StatusCode == http.StatusNotModified {
		cache := t.(*confCache)
		glg.Debugf("Server return not modified, etag: ", cache.eTag)
		return cache.sac, false, nil
	}

	// if server return any error
	if r.StatusCode != http.StatusOK {
		glg.Error("Server return not OK")
		return nil, false, errors.Wrap(ErrFetchAthenzConf, "http return status not OK")
	}

	sac := new(SysAuthConfig)
	if err = json.NewDecoder(r.Body).Decode(&sac); err != nil {
		glg.Errorf("Error decoding public key entries, err: %v", err)
		return nil, false, errors.Wrap(err, "json format not correct")
	}

	if _, err = io.Copy(ioutil.Discard, r.Body); err != nil {
		glg.Warn(errors.Wrap(err, "error io.copy"))
	}
	if err = r.Body.Close(); err != nil {
		glg.Warn(errors.Wrap(err, "error body.close"))
	}

	// set eTag cache
	eTag := r.Header.Get("ETag")
	if eTag != "" {
		glg.Debugf("Setting ETag %v", eTag)
		c.etagCache.SetWithExpire(string(env), &confCache{eTag, sac}, c.etagExpTime)
	}

	glg.Info("Fetch public key entries success")
	return sac, true, nil
}

func (c *confd) getPubKey(env AthenzEnv, keyID string) authcore.Verifier {
	if env == EnvZTS {
		ver, ok := c.confCache.ZTSPubKeys.Load(keyID)
		if !ok {
			glg.Warnf("ZTS PubKey Load Failed keyID[%s]  getZTSPubKey %v", keyID, ver)
			return nil
		}
		return ver.(authcore.Verifier)
	}

	ver, ok := c.confCache.ZMSPubKeys.Load(keyID)
	if !ok {
		glg.Warnf("ZMS PubKey Load Failed keyID[%s]  getZMSPubKey %v", keyID, ver)
		return nil
	}
	return ver.(authcore.Verifier)
}
