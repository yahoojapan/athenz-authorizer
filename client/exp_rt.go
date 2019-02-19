package client

import (
	"io"
	"io/ioutil"
	"math"
	"net/http"
	"time"
)

type ExponentialRoundTripper struct {
	transport http.RoundTripper

	backoffDtFactor float64
	maxRetryCount   int
	maxRetryTime    time.Duration
}

var retriableStatuses = map[int]struct{}{
	http.StatusTooManyRequests:     struct{}{},
	http.StatusInternalServerError: struct{}{},
	http.StatusServiceUnavailable:  struct{}{},
	http.StatusGatewayTimeout:      struct{}{},
}

func NewExponentialRoundTripper(transport http.RoundTripper, backoffFactor float64, maxRetryCount int, maxRetryTime time.Duration) (*ExponentialRoundTripper, error) {
	// Pre-calculate the time factor for calculating the delta wait duration used in calNextWaitDur(int) method.
	// Originally the formula of calculating wait duration is [ dt = ( ((count + 1) / factor) * √t ) ^ 2 - ( (count / factor) * √t ) ^ 2 ],
	// but we can simpliy the formula to [ dt = (2 * count + 1) * (t / factor ^ 2) ]
	f := float64(time.Second) / math.Pow(backoffFactor, 2.0)

	return &ExponentialRoundTripper{
		transport:       transport,
		backoffDtFactor: f,
		maxRetryCount:   maxRetryCount,
		maxRetryTime:    maxRetryTime,
	}, nil
}

func (p *ExponentialRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	timeLimit := time.Now().Add(p.maxRetryTime).UnixNano()
	var resp *http.Response
	var err error

	for cnt := 0; cnt < p.maxRetryCount; cnt++ {
		resp, err = p.transport.RoundTrip(req)
		dur := p.calNextWaitDur(cnt)

		if err != nil {
			if !isTemporary(err) {
				return nil, err
			}

			if !canRetry(dur, timeLimit) {
				return nil, err
			}

			time.Sleep(dur)
			continue
		}

		if responseRetriable(resp) {
			continue
		}

		// response success
		io.Copy(ioutil.Discard, resp.Body)
		resp.Body.Close()
		return resp, nil
	}

	return resp, err
}

func (p *ExponentialRoundTripper) calNextWaitDur(count int) time.Duration {
	// 	return time.Duration(math.Pow((float64(count)/p.backoffFactor), 2) * float64(time.Second))
	return time.Duration(float64(2*count+1) * p.backoffDtFactor)
}

// sleep return false if ( Now + wait duration > time limit )
// otherwise it return true
func canRetry(dur time.Duration, timeLimit int64) bool {
	return time.Now().Add(dur).UnixNano() < timeLimit
}

func responseRetriable(r *http.Response) bool {
	_, ok := retriableStatuses[r.StatusCode]
	return ok
}

type temporaryer interface {
	Temporary() bool
}

func isTemporary(err error) bool {
	e, ok := err.(temporaryer)
	return ok && e.Temporary()
}
