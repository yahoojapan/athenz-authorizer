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

	jwt "github.com/golang-jwt/jwt"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/pkg/errors"
	"github.com/yahoojapan/athenz-authorizer/v5/jwk"
)

const (
	confirmMethodMember = "x5t#S256"
)

// errNilHeader is "header is nil"
var errNilHeader = errors.New("header is nil")

// errKeyNotFoundInHeader is "key not written in header"
var errKeyNotFoundInHeader = errors.New("key not written in header")

// errHeaderValueNotString is "header value not written as string"
var errHeaderValueNotString = errors.New("header value not written as string")

// Processor represents the access token parser interface.
type Processor interface {
	ParseAndValidateOAuth2AccessToken(cred string, cert *x509.Certificate) (*OAuth2AccessTokenClaim, error)
}

type atp struct {
	jwkp                                  jwk.Provider
	enableMTLSCertificateBoundAccessToken bool
	// If you go back to the issue time, set that time. Subtract if necessary (for example, token issuance time).
	clientCertificateGoBackSeconds int64
	// The number of seconds to allow for a failed CNF check due to a client certificate being updated.
	clientCertificateOffsetSeconds int64
	enableVerifyClientID           bool
	authorizedClientIDs            map[string][]string
}

// New returns the Processor instance.
func New(opts ...Option) (Processor, error) {
	a := new(atp)
	for _, opt := range append(defaultOptions, opts...) {
		if err := opt(a); err != nil {
			return nil, errors.Wrap(err, "error create access token processor")
		}
	}
	return a, nil
}

func (a *atp) ParseAndValidateOAuth2AccessToken(cred string, cert *x509.Certificate) (*OAuth2AccessTokenClaim, error) {

	tok, err := jwt.ParseWithClaims(cred, &OAuth2AccessTokenClaim{}, a.keyFunc)
	if err != nil {
		return nil, err
	}
	claims, ok := tok.Claims.(*OAuth2AccessTokenClaim)
	if !ok || !tok.Valid {
		return nil, errors.New("error invalid access token")
	}

	// validate client_id of AccessToken
	if a.enableVerifyClientID {
		err := a.validateClientID(cert, claims)
		if err != nil {
			return nil, err
		}
	}

	// certificate bound access token
	if a.enableMTLSCertificateBoundAccessToken {
		err := a.validateCertificateBoundAccessToken(cert, claims)
		if err != nil {
			return nil, err
		}
	}

	return claims, nil
}

func (a *atp) validateClientID(cert *x509.Certificate, claims *OAuth2AccessTokenClaim) error {
	if cert == nil {
		return errors.New("error mTLS client certificate is nil")
	}
	if claims == nil {
		return errors.New("error claim of access token is nil")
	}

	cn := cert.Subject.CommonName
	clientID := claims.ClientID
	clientIDs := a.authorizedClientIDs[cn]

	for _, v := range clientIDs {
		if v == clientID {
			return nil
		}
	}
	return errors.Errorf("error %v is not authorized %v", clientID, cn)
}

func (a *atp) validateCertificateBoundAccessToken(cert *x509.Certificate, claims *OAuth2AccessTokenClaim) error {
	if cert == nil {
		return errors.New("error mTLS client certificate is nil")
	}
	if claims == nil {
		return errors.New("error claim of access token is nil")
	}

	certThumbprint, ok := claims.Confirm[confirmMethodMember]
	if !ok {
		return errors.New("error token is not certificate bound access token")
	}

	// cnf check
	sum := sha256.Sum256(cert.Raw)
	if base64.RawURLEncoding.EncodeToString(sum[:]) == certThumbprint {
		return nil
	}

	// If cnf check fails, check to allow if the certificate has been refresh
	if err := a.validateCertPrincipal(cert, claims); err != nil {
		return err
	}

	// auth_core is validating the proxy principal here.(future work)

	return nil
}

func (a *atp) validateCertPrincipal(cert *x509.Certificate, claims *OAuth2AccessTokenClaim) error {
	if a.clientCertificateOffsetSeconds == 0 {
		return errors.New("error validate cert thumbprint failed. also, clientCertificateOffsetSeconds is 0. cert refresh check is disabled")
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
	certActualIssueTime := cert.NotBefore.Unix() + a.clientCertificateGoBackSeconds
	// Issue time check. If the certificate had been updated, it would have been issued later than the token.
	if certActualIssueTime < atIssueTime {
		return errors.Errorf("error certificate: issued before access token: cert = %v, tok = %v", certActualIssueTime, atIssueTime)
	}
	// Issue time check. Determine if certificate's issue time is within an allowed range
	if certActualIssueTime > atIssueTime+a.clientCertificateOffsetSeconds {
		return errors.Errorf("error certificate: access token too old: cert = %v, offset = %v, tok = %v", certActualIssueTime, a.clientCertificateOffsetSeconds, atIssueTime)
	}
	return nil
}

// keyFunc extract the key id from the token, and return corresponding key
func (a *atp) keyFunc(token *jwt.Token) (interface{}, error) {
	keyID, err := getAsStringFromHeader(&token.Header, jws.KeyIDKey)
	// kid is required and will return if an error occurs
	if err != nil {
		return nil, errors.New(err.Error() + ":" + jws.KeyIDKey)
	}

	jwkSetURL, err := getAsStringFromHeader(&token.Header, jws.JWKSetURLKey)
	// return not string error or nil header error.
	// If not found error, assume it is an athenz token and continue.
	if err == errHeaderValueNotString || err == errNilHeader {
		return nil, errors.New(err.Error() + ":" + jws.JWKSetURLKey)
	}

	key := a.jwkp(keyID, jwkSetURL)

	if key == nil {
		return nil, errors.Errorf("key cannot be found, keyID: %s jwkSetURL: %s", keyID, jwkSetURL)
	}

	return key, nil
}

// getAsStringFromHeader return string header value and error.
// return error is not found or not string cases.
func getAsStringFromHeader(header *map[string]interface{}, key string) (string, error) {
	var ok bool

	if header == nil {
		return "", errNilHeader
	}

	var v interface{}
	if v, ok = (*header)[key]; !ok {
		return "", errKeyNotFoundInHeader
	}

	var value string
	if value, ok = v.(string); !ok {
		return "", errHeaderValueNotString
	}

	return value, nil
}
