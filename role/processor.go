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
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
	"github.com/yahoojapan/athenz-authorizer/v2/jwk"
	"github.com/yahoojapan/athenz-authorizer/v2/pubkey"
)

var (
	confirmationMethod = "x5t#S256"
)

// Processor represents the role token parser interface.
type Processor interface {
	ParseAndValidateRoleToken(tok string) (*Token, error)
	ParseAndValidateRoleJWT(cred string) (*RoleJWTClaim, error)
	ParseAndValidateAccessToken(cred string, cert *x509.Certificate) (*AccessTokenClaim, error)
}

type rtp struct {
	pkp                                   pubkey.Provider
	jwkp                                  jwk.Provider
	enableMTLSCertificateBoundAccessToken bool
	// If you go back to the issue time, set that time. Subtract if necessary (for example, token issuance time).
	clientCertificateGoBackSeconds int64
	// The number of seconds to allow for a failed CNF check due to a client certificate being updated.
	clientCertificateOffsetSeconds int64
}

// New returns the Role instance.
func New(opts ...Option) Processor {
	r := new(rtp)
	for _, opt := range append(defaultOptions, opts...) {
		opt(r)
	}
	return r
}

// ParseAndValidateRoleToken return the parsed and validated role token, and return any parsing and validate errors.
func (r *rtp) ParseAndValidateRoleToken(tok string) (*Token, error) {
	rt, err := r.parseToken(tok)
	if err != nil {
		return nil, errors.Wrap(err, "error parse role token")
	}

	if err = r.validate(rt); err != nil {
		return nil, errors.Wrap(err, "error validate role token")
	}
	return rt, nil
}

func (r *rtp) parseToken(tok string) (*Token, error) {
	st := strings.SplitN(tok, ";s=", 2)
	if len(st) != 2 {
		return nil, errors.Wrap(ErrRoleTokenInvalid, "no signature found")
	}

	rt := &Token{
		UnsignedToken: st[0],
		Signature:     st[1],
	}

	for _, pair := range strings.Split(st[0], ";") {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) != 2 {
			return nil, errors.Wrap(ErrRoleTokenInvalid, "invalid key value format")
		}
		if err := rt.SetParams(kv[0], kv[1]); err != nil {
			return nil, errors.Wrap(err, "error setting value")
		}
	}

	return rt, nil
}

func (r *rtp) ParseAndValidateRoleJWT(cred string) (*RoleJWTClaim, error) {
	tok, err := jwt.ParseWithClaims(cred, &RoleJWTClaim{}, r.keyFunc)
	if err != nil {
		return nil, err
	}

	if claims, ok := tok.Claims.(*RoleJWTClaim); ok && tok.Valid {
		return claims, nil
	}

	return nil, errors.New("error invalid jwt token")
}

func (r *rtp) validate(rt *Token) error {
	if rt.Expired() {
		return errors.Wrapf(ErrRoleTokenExpired, "token expired")
	}
	ver := r.pkp(pubkey.EnvZTS, rt.KeyID)
	if ver == nil {
		return errors.Wrapf(ErrRoleTokenInvalid, "invalid role token key ID %s", rt.KeyID)
	}
	return ver.Verify(rt.UnsignedToken, rt.Signature)
}

func (r *rtp) ParseAndValidateAccessToken(cred string, cert *x509.Certificate) (*AccessTokenClaim, error) {

	tok, err := jwt.ParseWithClaims(cred, &AccessTokenClaim{}, r.keyFunc)
	if err != nil {
		return nil, err
	}
	claims, ok := tok.Claims.(*AccessTokenClaim)
	if !ok || !tok.Valid {
		return nil, errors.New("error invalid access token")
	}

	// certificate bound access token
	if r.enableMTLSCertificateBoundAccessToken {
		err := r.validateCertificateBoundAccessToken(cert, claims)
		if err != nil {
			return nil, err
		}
	}

	return claims, nil
}

func (r *rtp) validateCertificateBoundAccessToken(cert *x509.Certificate, claims *AccessTokenClaim) error {
	if cert == nil {
		return errors.New("error mTLS client certificate is nil")
	}

	if _, ok := claims.Confirm[confirmationMethod]; !ok {
		return errors.New("error token is not certificate bound access token")
	}

	// cnf check
	sum := sha256.Sum256(cert.Raw)
	if base64.URLEncoding.EncodeToString(sum[:]) == claims.Confirm[confirmationMethod] {
		return nil
	}

	// If cnf check fails, check to allow if the certificate has been refresh
	if err := r.validateCertPrincipal(cert, claims); err != nil {
		return err
	}

	// auth_core is validating the proxy principal here.(future work)

	return nil
}

func (r *rtp) validateCertPrincipal(cert *x509.Certificate, claims *AccessTokenClaim) error {
	// common name check
	cn := cert.Subject.CommonName
	if cn != "" {
		return errors.New("error subject common name of client certificate is empty")
	}
	clientID := claims.ClientID
	if clientID != "" {
		return errors.New("error client_id of access token is empty")
	}
	if cn != clientID {
		return errors.Errorf("error certificate and access token principal mismatch: %v vs %v", cn, clientID)
	}

	// Issue time check. If the certificate had been updated, it would have been issued later than the token.
	if cert.NotBefore.Unix() < claims.IssuedAt-r.clientCertificateGoBackSeconds {
		return errors.Errorf("error certificate: %v issued before token: %v", cert.NotBefore.Unix(), claims.IssuedAt)
	}
	// Issue tiem check. Determine if certificate's issue time is within an allowed range
	if cert.NotBefore.Unix() > claims.IssuedAt+r.clientCertificateOffsetSeconds-r.clientCertificateGoBackSeconds {
		return errors.Errorf("Certificate: %v past configured offset %v for token: %v", cert.NotBefore.Unix(), r.clientCertificateOffsetSeconds, claims.IssuedAt)
	}
	return nil
}

// keyFunc extract the key id from the token, and return corresponding key
func (r *rtp) keyFunc(token *jwt.Token) (interface{}, error) {
	keyID, ok := token.Header["kid"]
	if !ok {
		return nil, errors.New("kid not written in header")
	}

	key := r.jwkp(keyID.(string))
	if key == nil {
		return nil, errors.Errorf("key cannot be found, keyID: %s", keyID)
	}

	return key, nil
}
