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

package access

import (
	"time"

	"github.com/pkg/errors"
	"github.com/yahoojapan/athenz-authorizer/v2/jwk"
)

var (
	defaultOptions = []Option{}
)

// Option represents a functional options pattern interface
type Option func(*atp) error

// WithJWKProvider represents set pubkey provider functional option
func WithJWKProvider(jwkp jwk.Provider) Option {
	return func(r *atp) error {
		r.jwkp = jwkp
		return nil
	}
}

// WithEnableMTLSCertificateBoundAccessToken represents set enableMTLSCertificateBoundAccessToken functional option
func WithEnableMTLSCertificateBoundAccessToken(b bool) Option {
	return func(r *atp) error {
		r.enableMTLSCertificateBoundAccessToken = b
		return nil
	}
}

// WithEnableVerifyTokenClientID represents set enableVerifyTokenClientID functional option
func WithEnableVerifyTokenClientID(b bool) Option {
	return func(r *atp) error {
		r.enableVerifyTokenClientID = b
		return nil
	}
}

// WithAuthorizedPrincipals represents set authorizedPrincipals functional option
func WithAuthorizedPrincipals(m map[string][]string) Option {
	return func(r *atp) error {
		r.authorizedPrincipals = m
		return nil
	}
}

// WithClientCertificateGoBackSeconds represents set clientCertificateGoBackSeconds functional option
func WithClientCertificateGoBackSeconds(t string) Option {
	return func(r *atp) error {
		if t == "" {
			return nil
		}
		rd, err := time.ParseDuration(t)
		if err != nil {
			return errors.Wrap(err, "invalid refresh duration")
		}
		r.clientCertificateGoBackSeconds = int64(rd.Seconds())
		return nil
	}
}

// WithClientCertificateOffsetSeconds represents set clientCertificateOffsetSeconds functional option
func WithClientCertificateOffsetSeconds(t string) Option {
	return func(r *atp) error {
		if t == "" {
			return nil
		}
		rd, err := time.ParseDuration(t)
		if err != nil {
			return errors.Wrap(err, "invalid offset duration")
		}
		r.clientCertificateOffsetSeconds = int64(rd.Seconds())
		return nil
	}
}
