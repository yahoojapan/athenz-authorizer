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

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/pkg/errors"
	"github.com/yahoojapan/athenz-authorizer/v2/access"
	"github.com/yahoojapan/athenz-authorizer/v2/jwk"
	"github.com/yahoojapan/athenz-authorizer/v2/pubkey"
	"github.com/yahoojapan/athenz-authorizer/v2/role"
)

type ConfdMock struct {
	pubkey.Daemon
	confdExp time.Duration
}

func (cm *ConfdMock) Start(ctx context.Context) <-chan error {
	ech := make(chan error, 1)
	go func() {
		time.Sleep(cm.confdExp)
		ech <- errors.New("pubkey error")
	}()
	return ech
}

type PubkeydMock struct {
	StartFunc       func(context.Context) <-chan error
	UpdateFunc      func(context.Context) error
	GetProviderFunc func() pubkey.Provider
}

func (pm *PubkeydMock) Start(ctx context.Context) <-chan error {
	if pm.StartFunc != nil {
		return pm.StartFunc(ctx)
	}
	return nil
}

func (pm *PubkeydMock) Update(ctx context.Context) error {
	if pm.UpdateFunc != nil {
		return pm.UpdateFunc(ctx)
	}
	return nil
}

func (pm *PubkeydMock) GetProvider() pubkey.Provider {
	if pm.GetProviderFunc != nil {
		return pm.GetProviderFunc()
	}
	return nil
}

type PolicydMock struct {
	UpdateFunc      func(context.Context) error
	CheckPolicyFunc func(ctx context.Context, domain string, roles []string, action, resource string) error

	policydExp  time.Duration
	policyCache map[string]interface{}
}

func (pdm *PolicydMock) Start(context.Context) <-chan error {
	ech := make(chan error, 1)
	go func() {
		time.Sleep(pdm.policydExp)
		ech <- errors.New("policyd error")
	}()
	return ech
}

func (pdm *PolicydMock) Update(ctx context.Context) error {
	if pdm.UpdateFunc != nil {
		return pdm.UpdateFunc(ctx)
	}
	return nil
}

func (pdm *PolicydMock) CheckPolicy(ctx context.Context, domain string, roles []string, action, resource string) error {
	if pdm.CheckPolicyFunc != nil {
		return pdm.CheckPolicyFunc(ctx, domain, roles, action, resource)
	}
	return nil
}

func (pdm *PolicydMock) GetPolicyCache(ctx context.Context) map[string]interface{} {
	return pdm.policyCache
}

type RoleProcessorMock struct {
	role.Processor
	wantErr error
	rt      *role.Token
	rjc     *role.RoleJWTClaim
}

func (rpm *RoleProcessorMock) ParseAndValidateRoleToken(tok string) (*role.Token, error) {
	return rpm.rt, rpm.wantErr
}

func (rpm *RoleProcessorMock) ParseAndValidateRoleJWT(cred string) (*role.RoleJWTClaim, error) {
	return rpm.rjc, rpm.wantErr
}

type AccessProcessorMock struct {
	access.Processor
	wantErr error
	act     *access.OAuth2AccessTokenClaim
}

func (apm *AccessProcessorMock) ParseAndValidateOAuth2AccessToken(cred string, cert *x509.Certificate) (*access.OAuth2AccessTokenClaim, error) {
	return apm.act, apm.wantErr
}

type JwkdMock struct {
	StartFunc       func(context.Context) <-chan error
	UpdateFunc      func(context.Context) error
	GetProviderFunc func() jwk.Provider
}

func (jm *JwkdMock) Start(ctx context.Context) <-chan error {
	if jm.StartFunc != nil {
		return jm.StartFunc(ctx)
	}
	return nil
}

func (jm *JwkdMock) Update(ctx context.Context) error {
	if jm.UpdateFunc != nil {
		return jm.UpdateFunc(ctx)
	}
	return nil
}

func (jm *JwkdMock) GetProvider() jwk.Provider {
	if jm.GetProviderFunc != nil {
		return jm.GetProviderFunc()
	}
	return nil
}
