package config

type SysAuthConfig struct {
	Modified   string       `json:"modified"`
	Name       string       `json:"name"`
	PublicKeys []*PublicKey `json:"publicKeys"`
}

type PublicKey struct {
	ID  string `json:"id"`
	Key string `json:"key"`
}
