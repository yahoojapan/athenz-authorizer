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

import "context"

// fetcherMock is the adapter implementation of Fetcher interface for mocking.
type fetcherMock struct {
	domainMock         func() string
	fetchMock          func(context.Context) (*SignedPolicy, error)
	fetchWithRetryMock func(context.Context) (*SignedPolicy, error)
}

// Domain is just an adapter.
func (r *fetcherMock) Domain() string {
	return r.domainMock()
}

// Fetch is just an adapter.
func (r *fetcherMock) Fetch(ctx context.Context) (*SignedPolicy, error) {
	return r.fetchMock(ctx)
}

// FetchWithRetry is just an adapter.
func (r *fetcherMock) FetchWithRetry(ctx context.Context) (*SignedPolicy, error) {
	return r.fetchWithRetryMock(ctx)
}

// readCloserMock is the adapter implementation of io.ReadCloser interface for mocking.
type readCloserMock struct {
	readMock  func(p []byte) (n int, err error)
	closeMock func() error
}

// Read is just an adapter.
func (r *readCloserMock) Read(p []byte) (n int, err error) {
	return r.readMock(p)
}

// Close is just an adapter.
func (r *readCloserMock) Close() error {
	return r.closeMock()
}
