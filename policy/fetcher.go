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

package policy

import (
	"unsafe"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/kpango/fastime"
	"github.com/kpango/glg"
	"github.com/pkg/errors"
)

// SignedPolicyVerifier type defines the function signature to verify a signed policy.
type SignedPolicyVerifier func(*SignedPolicy) error

// Fetcher represents a daemon for user to verify the role token
type Fetcher interface {
	Domain() string
	Fetch(context.Context) (*SignedPolicy, error)
	FetchWithRetry(context.Context) (*SignedPolicy, error)
}

type fetcher struct {

	// etag related
	expireMargin time.Duration

	// retry related
	retryInterval time.Duration
	retryMaxCount int

	// athenz related
	domain     string
	athenzURL  string
	spVerifier SignedPolicyVerifier

	client      *http.Client
	policyCache unsafe.Pointer
}

type taggedPolicy struct {
	etag       string
	etagExpiry time.Time
	sp         *SignedPolicy
	ctime      time.Time
}

func (f *fetcher) Domain() string {
	return f.domain
}

// Fetch fetches the policy. When calling concurrently, it is not guarantee that the cache will always keep the latest version.
func (f *fetcher) Fetch(ctx context.Context) (*SignedPolicy, error) {
	glg.Infof("will fetch policy for domain: %s", f.domain)
	// https://{www.athenz.com/zts/v1}/domain/{athenz domain}/signed_policy_data
	url := fmt.Sprintf("https://%s/domain/%s/signed_policy_data", f.athenzURL, f.domain)

	glg.Debugf("will fetch policy from url: %s", url)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		errMsg := "create fetch policy request fail"
		glg.Errorf("%s, domain: %s, error: %v", errMsg, f.domain, err)
		return nil, errors.Wrap(err, errMsg)
	}

	// etag header
	var tp *taggedPolicy
	if f.policyCache != nil {
		tp = (*taggedPolicy)(atomic.LoadPointer(&f.policyCache))
		if tp.etag != "" && tp.etagExpiry.After(fastime.Now()) {
			glg.Debugf("request on domain: %s, with etag: %s", f.domain, tp.etag)
			req.Header.Set("If-None-Match", tp.etag)
		}
	}

	res, err := f.client.Do(req.WithContext(ctx))
	if err != nil {
		errMsg := "fetch policy HTTP request fail"
		glg.Errorf("%s, domain: %s, error: %v", errMsg, f.domain, err)
		return nil, errors.Wrap(err, errMsg)
	}
	defer func() {
		if err := flushAndClose(res.Body); err != nil {
			glg.Warn(errors.Wrap(err, "close Response.Body fail"))
		}
	}()

	// if server responses NotModified, return policy from cache
	if res.StatusCode == http.StatusNotModified {
		glg.Debugf("policy = 304 not modified, use cache for domain: %s, etag: %v", f.domain, tp.etag)
		return tp.sp, nil
	}

	if res.StatusCode != http.StatusOK {
		errMsg := "fetch policy HTTP response != 200 OK"
		glg.Errorf("%s, domain: %s, status: %d", errMsg, f.domain, res.StatusCode)
		return nil, errors.Wrap(ErrFetchPolicy, errMsg)
	}

	// read and decode
	sp := new(SignedPolicy)
	if err = json.NewDecoder(res.Body).Decode(&sp); err != nil {
		errMsg := "policy decode fail"
		glg.Errorf("%s, domain: %s, error: %v", errMsg, f.domain, err)
		return nil, errors.Wrap(err, errMsg)
	}

	// verify policy data
	if err = f.spVerifier(sp); err != nil {
		errMsg := "invalid policy"
		glg.Errorf("%s, domain: %s, error: %v", errMsg, f.domain, err)
		return nil, errors.Wrap(err, errMsg)
	}

	// set policy cache
	etag := res.Header.Get("ETag")
	etagExpiry := sp.SignedPolicyData.Expires.Time.Add(-f.expireMargin)
	newTp := taggedPolicy{
		etag:       etag,
		etagExpiry: etagExpiry,
		sp:         sp,
		ctime:      fastime.Now(),
	}
	glg.Debugf("set policy cache for domain: %s, policy: %v", f.domain, newTp)
	atomic.StorePointer(&f.policyCache, unsafe.Pointer(&newTp))

	return sp, nil
}

func (f *fetcher) FetchWithRetry(ctx context.Context) (*SignedPolicy, error) {
	var lastErr error
	for i := -1; i < f.retryMaxCount; i++ {
		sp, err := f.Fetch(ctx)
		if err == nil {
			return sp, nil
		}

		lastErr = err
		time.Sleep(f.retryInterval)
	}

	errMsg := "max. retry count excess"
	glg.Info("Will use policy cache, since: %s, domain: %s, error: %v", errMsg, f.domain, lastErr)
	if lastErr == nil {
		lastErr = fmt.Errorf("retryMaxCount %v", f.retryMaxCount)
	}
	if f.policyCache == nil {
		return nil, errors.Wrap(errors.Wrap(lastErr, errMsg), "no policy cache")
	}
	return (*taggedPolicy)(atomic.LoadPointer(&f.policyCache)).sp, errors.Wrap(lastErr, errMsg)
}

// flushAndClose helps to flush and close a ReadCloser. Used for request body internal.
// Returns if there is any errors.
func flushAndClose(rc io.ReadCloser) error {
	if rc != nil {
		// flush
		_, err := io.Copy(ioutil.Discard, rc)
		if err != nil {
			return err
		}
		// close
		return rc.Close()
	}
	return nil
}
