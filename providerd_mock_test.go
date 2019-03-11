package providerd

import (
	"context"
	"time"

	"github.com/kpango/glg"
	"github.com/pkg/errors"
	"github.com/yahoojapan/athenz-policy-updater/config"
	"github.com/yahoojapan/athenz-policy-updater/policy"
	"github.com/yahoojapan/athenz-policy-updater/role"
)

type ConfdMock struct {
	config.AthenzConfd
	confdExp time.Duration
}

func (cm *ConfdMock) StartConfUpdator(ctx context.Context) <-chan error {
	ech := make(chan error, 1)
	go func() {
		time.Sleep(cm.confdExp)
		ech <- errors.New("confd error")
	}()
	return ech
}

type PolicydMock struct {
	policy.Policyd
	policydExp time.Duration
	wantErr    error
}

func (pm *PolicydMock) StartPolicyUpdator(context.Context) <-chan error {
	ech := make(chan error, 1)
	go func() {
		time.Sleep(pm.policydExp)
		ech <- errors.New("policyd error")
	}()
	return ech
}

func (pm *PolicydMock) CheckPolicy(ctx context.Context, domain string, roles []string, action, resource string) error {
	return pm.wantErr
}

type RoleTokenMock struct {
	role.RoleTokenParser
	wantErr error
	rt      *role.RoleToken
}

func (rm *RoleTokenMock) ParseAndValidateRoleToken(tok string) (*role.RoleToken, error) {
	glg.Debugf("test %v", rm.wantErr)
	return rm.rt, rm.wantErr
}
