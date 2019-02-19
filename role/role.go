package role

import (
	"strings"

	"github.com/yahoojapan/athenz-policy-updater/config"
	"github.com/pkg/errors"
)

type RoleTokenParser interface {
	ParseAndValidateRoleToken(tok string) (*RoleToken, error)
}

type rtp struct {
	pkp config.PubKeyProvider
}

func NewRoleTokenParser(prov config.PubKeyProvider) RoleTokenParser {
	return &rtp{
		pkp: prov,
	}
}

func (r *rtp) ParseAndValidateRoleToken(tok string) (*RoleToken, error) {
	rt, err := r.parseRoleToken(tok)
	if err != nil {
		return nil, errors.Wrap(err, "error parse role token")
	}

	if err = r.validate(rt); err != nil {
		return nil, errors.Wrap(err, "error validate role token")
	}
	return rt, nil
}

func (r *rtp) parseRoleToken(tok string) (*RoleToken, error) {
	st := strings.SplitN(tok, ";s=", 2)
	if len(st) != 2 {
		return nil, errors.Wrap(ErrRoleTokenInvalid, "no signature found")
	}

	rt := &RoleToken{
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

func (r *rtp) validate(rt *RoleToken) error {
	if rt.Expired() {
		return errors.Wrapf(ErrRoleTokenExpired, "token expired")
	}
	ver := r.pkp(config.EnvZTS, rt.KeyID)
	if ver == nil {
		return errors.Wrapf(ErrRoleTokenInvalid, "invalid role token key ID %s", rt.KeyID)
	}
	return ver.Verify(rt.UnsignedToken, rt.Signature)
}
