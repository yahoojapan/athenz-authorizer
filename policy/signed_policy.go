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
	"encoding/json"

	"github.com/pkg/errors"
	"github.com/yahoojapan/athenz-policy-updater/config"

	"github.com/yahoo/athenz/utils/zpe-updater/util"
)

// SignedPolicy represents the signed policy data
type SignedPolicy struct {
	util.DomainSignedPolicyData
}

// Verify verifies the signed policy and return any errors
func (s *SignedPolicy) Verify(pkp config.PubKeyProvider) error {
	// verify signed policy data
	ver := pkp(config.EnvZTS, s.KeyId)
	if ver == nil {
		return errors.New("zts key not found")
	}
	spd, err := json.Marshal(s.SignedPolicyData)
	if err != nil {
		return errors.New("error marshal signed policy data")
	}
	if err := ver.Verify((string)(spd), s.Signature); err != nil {
		//if err := ver.Verify(*(*string)(unsafe.Pointer(s.SignedPolicyData)), s.Signature); err != nil {
		return errors.Wrap(err, "error verify signature")
	}

	// verify policy data
	ver = pkp(config.EnvZMS, s.SignedPolicyData.ZmsKeyId)
	if ver == nil {
		return errors.New("zms key not found")
	}
	pd, err := json.Marshal(s.SignedPolicyData.PolicyData)
	if err != nil {
		return errors.New("error marshal policy data")
	}
	if err := ver.Verify((string)(pd), s.SignedPolicyData.ZmsSignature); err != nil {
		return errors.Wrap(err, "error verify zms signature")
	}
	return nil
}
