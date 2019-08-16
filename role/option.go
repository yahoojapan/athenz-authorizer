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

package role

import (
	"github.com/yahoojapan/athenz-authorizer/jwk"
	"github.com/yahoojapan/athenz-authorizer/pubkey"
)

var (
	defaultOptions = []Option{}
)

// Option represents a functional options pattern interface
type Option func(*rtp)

// WithPubkeyProvider represents set pubkey provider functional option
func WithPubkeyProvider(pkp pubkey.Provider) Option {
	return func(r *rtp) {
		r.pkp = pkp
	}
}

// WithJWKProvider represents set pubkey provider functional option
func WithJWKProvider(jwkp jwk.Provider) Option {
	return func(r *rtp) {
		r.jwkp = jwkp
	}
}
