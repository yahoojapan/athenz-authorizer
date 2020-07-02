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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/kpango/fastime"
	"github.com/kpango/glg"
	"github.com/pkg/errors"
)

// SignedPolicyVerifier type defines the function signature to verify a signed policy.
type SignedPolicyVerifier func(*SignedPolicy) error

// Fetcher represents fetcher object for fetching signed policy
type Fetcher interface {
	Domain() string
	Fetch(context.Context) (*SignedPolicy, error)
	FetchWithRetry(context.Context) (*SignedPolicy, error)
}

type fetcher struct {

	// ETag related
	expiryMargin time.Duration

	// retry related
	retryDelay    time.Duration
	retryAttempts int

	// athenz related
	domain     string
	athenzURL  string
	spVerifier SignedPolicyVerifier

	client      *http.Client
	policyCache unsafe.Pointer
}

type taggedPolicy struct {
	eTag       string
	eTagExpiry time.Time
	sp         *SignedPolicy
	ctime      time.Time
}

// Domain returns the fetcher domain
func (f *fetcher) Domain() string {
	return f.domain
}

// Fetch fetches the policy. When calling concurrently, it is not guarantee that the cache will always have the latest version.
func (f *fetcher) Fetch(ctx context.Context) (*SignedPolicy, error) {
	glg.Infof("will fetch policy for domain: %s", f.domain)
	// https://{athenz.io/zts/v1}/domain/{athenz domain}/signed_policy_data
	url := fmt.Sprintf("https://%s/domain/%s/signed_policy_data", f.athenzURL, f.domain)

	glg.Debugf("will fetch policy from url: %s", url)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		errMsg := "create fetch policy request fail"
		glg.Errorf("%s, domain: %s, error: %v", errMsg, f.domain, err)
		return nil, errors.Wrap(err, errMsg)
	}

	// ETag header
	var tp *taggedPolicy
	if f.policyCache != nil {
		tp = (*taggedPolicy)(atomic.LoadPointer(&f.policyCache))
		if tp.eTag != "" && tp.eTagExpiry.After(fastime.Now()) {
			glg.Debugf("request on domain: %s, with ETag: %s", f.domain, tp.eTag)
			req.Header.Set("If-None-Match", tp.eTag)
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
		glg.Debugf("policy = 304 not modified, use cache for domain: %s, ETag: %v", f.domain, tp.eTag)
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
	eTag := res.Header.Get("ETag")
	eTagExpiry := sp.SignedPolicyData.Expires.Time.Add(-f.expiryMargin)
	newTp := &taggedPolicy{
		eTag:       eTag,
		eTagExpiry: eTagExpiry,
		sp:         sp,
		ctime:      fastime.Now(),
	}
	glg.Debugf("set policy cache for domain: %s, policy: %s", f.domain, newTp)
	atomic.StorePointer(&f.policyCache, unsafe.Pointer(newTp))

	return sp, nil
}

// FetchWithRetry fetches policy with retry. Returns cached policy if all retries failed too.
func (f *fetcher) FetchWithRetry(ctx context.Context) (*SignedPolicy, error) {
	var lastErr error
	for i := -1; i < f.retryAttempts; i++ {
		sp, err := f.Fetch(ctx)
		if err == nil {
			return sp, nil
		}

		lastErr = err
		time.Sleep(f.retryDelay)
	}

	errMsg := "max. retry count excess"
	glg.Info("Will use policy cache, since: %s, domain: %s, error: %v", errMsg, f.domain, lastErr)
	if lastErr == nil {
		lastErr = fmt.Errorf("retryAttempts %v", f.retryAttempts)
	}
	if f.policyCache == nil {
		return nil, errors.Wrap(errors.Wrap(lastErr, errMsg), "no policy cache")
	}
	return (*taggedPolicy)(atomic.LoadPointer(&f.policyCache)).sp, errors.Wrap(lastErr, errMsg)
}

func (t *taggedPolicy) String() string {
	var policyDomain string
	if t.sp != nil && t.sp.SignedPolicyData != nil && t.sp.SignedPolicyData.PolicyData != nil {
		policyDomain = t.sp.SignedPolicyData.PolicyData.Domain
	}
	return fmt.Sprintf("{ ctime: %s, eTag: %s, eTagExpiry: %s, sp.domain: %s }", t.ctime.UTC().String(), t.eTag, t.eTagExpiry.UTC().String(), policyDomain)
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
