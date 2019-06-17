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
package jwk

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"unsafe"

	"github.com/pkg/errors"
)

type JWK struct {
	Keys   []jwk `json:"keys"`
	KeyMap map[string]jwk
}

type jwk struct {
	KeyType            string `json:"kty"`
	KeyID              string `json:"kid"`
	Algorithm          string `json:"alg"`
	Usage              string `json:"use"`
	Cruve              string `json:"crv"`
	X                  string `json:"x"`
	Y                  string `json:"y"`
	RSAModuleValue     string `json:"n"`
	RSAPublicExponsent string `json:"e"`
	publicKey          interface{}
}

func (j *JWK) Parse() (*JWK, error) {
	errs := make([]error, 0, len(j.Keys))
	j.KeyMap = make(map[string]jwk, len(j.Keys))
	for _, key := range j.Keys {
		block, rest := pem.Decode(*(*[]byte)(unsafe.Pointer(&key.KeyID)))
		if rest != nil {
			errs = append(errs, errors.New("failed to decode pem"))
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		key.Algorithm
		pk := cert.PublicKey.(*rsa.PublicKey)

	}
	return nil, nil
}
