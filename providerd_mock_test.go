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
package providerd

import (
	"context"
	"time"

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
	return rm.rt, rm.wantErr
}
