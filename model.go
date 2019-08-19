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

package authorizerd

type signedPolicy struct {
	KeyID            string `json:"keyId"`
	Signature        string `json:"signature"`
	SignedPolicyData struct {
		Expires    string `json:"expires"`
		Modified   string `json:"modified"`
		PolicyData struct {
			Domain   string `json:"domain"`
			Policies []struct {
				Assertions []struct {
					Action   string `json:"action"`
					Effect   string `json:"effect"`
					Resource string `json:"resource"`
					Role     string `json:"role"`
				} `json:"assertions"`
				Modified string `json:"modified"`
				Name     string `json:"name"`
			} `json:"policies"`
		} `json:"policyData"`
		ZmsKeyID     string `json:"zmsKeyId"`
		ZmsSignature string `json:"zmsSignature"`
	} `json:"signedPolicyData"`
}
