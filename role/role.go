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
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
	"github.com/yahoojapan/athenz-authorizer/jwk"
	"github.com/yahoojapan/athenz-authorizer/pubkey"
)

// Processor represents the role token parser interface.
type Processor interface {
	ParseAndValidateRoleToken(tok string) (*Token, error)
	ParseAndValidateRoleJWT(cred string) (*Claim, error)
}

type rtp struct {
	pkp  pubkey.Provider
	jwkp jwk.Provider
}

// New returns the Role instance.
func New(prov pubkey.Provider) Processor {
	return &rtp{
		pkp: prov,
	}
}

func (r *rtp) ParseAndValidateRoleJWT(cred string) (*Claim, error) {
	tok, err := jwt.ParseWithClaims(cred, &Claim{}, func(token *jwt.Token) (interface{}, error) {
		token.Method.Verify(token.SigningString(), token.Signature, r.jwkp(token.Method.Alg(), token.Header["kid"]))
		return nil, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := tok.Claims.(*Claim); ok && tok.Valid {
		return claims, nil
	}

	return nil, errors.New("error invalid jwt token")
}

// ParseAndValidateRoleToken return the parsed and validiated role token, and return any parsing and validate errors.
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
	}

	for _, pair := range strings.Split(tok, ";") {
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
