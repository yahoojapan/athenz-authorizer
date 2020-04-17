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
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
	"github.com/yahoojapan/athenz-authorizer/v2/jwk"
)

const (
	CONFIRM_METHOD_MEMBER = "x5t#S256"
)

// Processor represents the access token parser interface.
type Processor interface {
	ParseAndValidateOAuth2AccessToken(cred string, cert *x509.Certificate) (*OAuth2AccessTokenClaim, error)
}

type atp struct {
	jwkp                                  jwk.Provider
	enableMTLSCertificateBoundAccessToken bool
	enableVerifyTokenClientID             bool
	authorizedPrincipals                  map[string][]string
	// If you go back to the issue time, set that time. Subtract if necessary (for example, token issuance time).
	clientCertificateGoBackSeconds int64
	// The number of seconds to allow for a failed CNF check due to a client certificate being updated.
	clientCertificateOffsetSeconds int64
}

// New returns the Processor instance.
func New(opts ...Option) (Processor, error) {
	r := new(atp)
	for _, opt := range append(defaultOptions, opts...) {
		if err := opt(r); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func (r *atp) ParseAndValidateOAuth2AccessToken(cred string, cert *x509.Certificate) (*OAuth2AccessTokenClaim, error) {

	tok, err := jwt.ParseWithClaims(cred, &OAuth2AccessTokenClaim{}, r.keyFunc)
	if err != nil {
		return nil, err
	}
	claims, ok := tok.Claims.(*OAuth2AccessTokenClaim)
	if !ok || !tok.Valid {
		return nil, errors.New("error invalid access token")
	}

	// validate client_id of AccessToken
	if r.enableVerifyTokenClientID {
		err := r.validateTokenClientID(cert, claims)
		if err != nil {
			return nil, err
		}
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

func (r *atp) validateTokenClientID(cert *x509.Certificate, claims *OAuth2AccessTokenClaim) error {
	if cert == nil {
		return errors.New("error mTLS client certificate is nil")
	}
	if claims == nil {
		return errors.New("error claim of access token is nil")
	}

	cn := cert.Subject.CommonName
	clientID := claims.ClientID
	clientIDs := r.authorizedPrincipals[cn]

	for _, v := range clientIDs {
		if v == clientID {
			return nil
		}
	}
	return errors.Errorf("error %v is not authorized %v", clientID, cn)
}

func (r *atp) validateCertificateBoundAccessToken(cert *x509.Certificate, claims *OAuth2AccessTokenClaim) error {
	if cert == nil {
		return errors.New("error mTLS client certificate is nil")
	}
	if claims == nil {
		return errors.New("error claim of access token is nil")
	}

	certThumbprint, ok := claims.Confirm[CONFIRM_METHOD_MEMBER]
	if !ok {
		return errors.New("error token is not certificate bound access token")
	}

	// cnf check
	sum := sha256.Sum256(cert.Raw)
	if base64.RawURLEncoding.EncodeToString(sum[:]) == certThumbprint {
		return nil
	}

	// If cnf check fails, check to allow if the certificate has been refresh
	if err := r.validateCertPrincipal(cert, claims); err != nil {
		return err
	}

	// auth_core is validating the proxy principal here.(future work)

	return nil
}

func (r *atp) validateCertPrincipal(cert *x509.Certificate, claims *OAuth2AccessTokenClaim) error {
	if r.clientCertificateOffsetSeconds == 0 {
		return errors.New("error clientCertificateOffsetSeconds is 0. cert refresh check is disabled")
	}
	// common name check
	cn := cert.Subject.CommonName
	if cn == "" {
		return errors.New("error subject common name of client certificate is empty")
	}
	clientID := claims.ClientID
	if clientID == "" {
		return errors.New("error client_id of access token is empty")
	}
	if cn != clientID {
		return errors.Errorf("error certificate and access token principal mismatch: %v vs %v", cn, clientID)
	}

	// usecase: new cert + old token, after certificate rotation
	atIssueTime := claims.IssuedAt
	certActualIssueTime := cert.NotBefore.Unix() + r.clientCertificateGoBackSeconds
	// Issue time check. If the certificate had been updated, it would have been issued later than the token.
	if certActualIssueTime < atIssueTime {
		return errors.Errorf("error certificate: issued before access token: cert = %v, tok = %v", certActualIssueTime, atIssueTime)
	}
	// Issue time check. Determine if certificate's issue time is within an allowed range
	if certActualIssueTime > atIssueTime+r.clientCertificateOffsetSeconds {
		return errors.Errorf("error certificate: access token too old: cert = %v, offset = %v, tok = %v", certActualIssueTime, r.clientCertificateOffsetSeconds, atIssueTime)
	}
	return nil
}

// keyFunc extract the key id from the token, and return corresponding key
func (r *atp) keyFunc(token *jwt.Token) (interface{}, error) {
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
