package providerd

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
