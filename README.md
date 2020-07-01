# Athenz authorizer

[![License: Apache](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square)](https://opensource.org/licenses/Apache-2.0)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/yahoojapan/athenz-authorizer?style=flat-square&label=Github%20version)](https://github.com/yahoojapan/athenz-authorizer/releases/latest)
[![CircleCI](https://circleci.com/gh/yahoojapan/athenz-authorizer.svg)](https://circleci.com/gh/yahoojapan/athenz-authorizer)
[![codecov](https://codecov.io/gh/yahoojapan/athenz-authorizer/branch/master/graph/badge.svg?token=2CzooNJtUu&style=flat-square)](https://codecov.io/gh/yahoojapan/athenz-authorizer)
[![Go Report Card](https://goreportcard.com/badge/github.com/yahoojapan/athenz-authorizer)](https://goreportcard.com/report/github.com/yahoojapan/athenz-authorizer)
[![GolangCI](https://golangci.com/badges/github.com/yahoojapan/athenz-authorizer.svg?style=flat-square)](https://golangci.com/r/github.com/yahoojapan/athenz-authorizer)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/828220605c43419e92fb0667876dd2d0)](https://www.codacy.com/app/i.can.feel.gravity/athenz-authorizer?utm_source=github.com&utm_medium=referral&utm_content=yahoojapan/athenz-authorizer&utm_campaign=Badge_Grade)
[![GoDoc](http://godoc.org/github.com/yahoojapan/athenz-authorizer?status.svg)](http://godoc.org/github.com/yahoojapan/athenz-authorizer)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-v2.0%20adopted-ff69b4.svg)](code_of_conduct.md)

<!-- TOC insertAnchor:false -->

- [Athenz authorizer](#athenz-authorizer)
    - [What is Athenz authorizer](#what-is-athenz-authorizer)
    - [Usage](#usage)
    - [How it works](#how-it-works)
        - [Athenz public key daemon](#athenz-public-key-daemon)
        - [Athenz policy daemon](#athenz-policy-daemon)
    - [Configuration](#configuration)
    - [License](#license)
    - [Contributor License Agreement](#contributor-license-agreement)
    - [About releases](#about-releases)
    - [Authors](#authors)

<!-- /TOC -->

## What is Athenz authorizer

Athenz authorizer is a library to cache the policies of [Athenz](https://github.com/yahoo/athenz) to authorizer authentication and authorization check of user request.

![Overview](./docs/assets/policy_updater_overview.png)

## Usage

To initialize authorizer.

```golang

// Initialize authorizerd
daemon, err := authorizerd.New(
    authorizerd.WithAthenzURL("www.athenz.io"), // set athenz URL
    authorizerd.WithAthenzDomains("domain1", "domain2" ... "domain N"), // set athenz domains
    authorizerd.WithPubkeyRefreshPeriod(time.Hour * 24), // set athenz public key refresh period
    authorizerd.WithPolicyRefreshPeriod(time.Hour), // set policy refresh period
)
if err != nil {
   // cannot initialize authorizer daemon
}

// Start authorizer daemon
ctx := context.Background() // user can control authorizer daemon lifetime using this context
errs := daemon.Start(ctx)
go func() {
    err := <-errs
    // user should handle errors return from the daemon
}()

// Verify role token
if err := daemon.VerifyRoleToken(ctx, roleTok, act, res); err != nil {
    // token not authorized
}
```

## How it works

To do the authentication and authorization check, the user needs to specify which [domain data](https://github.com/yahoo/athenz/blob/master/docs/data_model.md#data-model) to be cache. The authorizer will periodically refresh the policies and Athenz public key data to [verify and decode](https://github.com/yahoo/athenz/blob/master/docs/zpu_policy_file.md#zts-signature-validation) the domain data. The verified domain data will cache into the memory, and use for authentication and authorization check.

The authorizer contains two sub-module, Athenz public key daemon (pubkeyd) and Athenz policy daemon (policyd).

### Athenz public key daemon

Athenz public key daemon (pubkeyd) is responsible for periodically update the Athenz public key data from Athenz server to verify the policy data received from Athenz policy daemon and verify the role token.

### Athenz policy daemon

Athenz policy daemon (policyd) is responsible for periodically update the policy data of specified Athenz domain from Athenz server. The received policy data will be verified using the public key got from pubkeyd, and cache into memory. Whenever user requesting for the access check, the verification check will be used instead of asking Athenz server every time.

## Configuration

The authorizer uses functional options pattern to initialize the instance. All the options are defined [here](./option.go).

| Option name           | Description                                                                                                        | Default Value                                                                                                                                                                                                                                                                                                         | Required | Example                |
| --------------------- | ------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- | ---------------------- |
| AthenzURL             | The Athenz server URL                                                                                              | "athenz.io/zts/v1"                                                                                                                                                                                                                                                                                                    | No       |                        |
| AthenzDomains         | Athenz domain name of Policy cache                                                                                 |                                                                                                                                                                                                                                                                                                                       | Yes      | "domName1", "domName2" |
| Transport             | The HTTP transport for getting policy data and Athenz public key data                                              | nil                                                                                                                                                                                                                                                                                                                   | No       |                        |
| CacheExp              | The TTL of the success cache                                                                                       | 1 Minute                                                                                                                                                                                                                                                                                                              | No       |                        |
| PubkeyRefreshPeriod   | The refresh period to update the Athenz public key data                                                            | 24 Hours                                                                                                                                                                                                                                                                                                              | No       |                        |
| PubkeySysAuthDomain   | System authority domain name to retrieve Athenz public key data                                                    | sys.auth                                                                                                                                                                                                                                                                                                              | No       |                        |
| PubkeyETagExpiry      | ETag cache TTL of Athenz public key data                                                                           | 168 Hours (1 Week)                                                                                                                                                                                                                                                                                                    | No       |                        |
| PubkeyETagPurgePeriod | ETag cache purge duration                                                                                          | 84 Hours                                                                                                                                                                                                                                                                                                              | No       |                        |
| PolicyRefreshPeriod   | The refresh period to update Athenz policy data                                                                    | 30 Minutes                                                                                                                                                                                                                                                                                                            | No       |                        |
| PolicyExpiryMargin    | The expiry margin to update the policy data. It forces update the policy data before the policy expiration margin. | 3 Hours                                                                                                                                                                                                                                                                                                               | No       |                        |
| AccessTokenParam      | Use access token verification. See [here](./option.go) for details of the options that can be specified.           | <table><tbody><tr><td>enable</td><td>true</td></tr><tr><td>verifyCertThumbprint</td><td>true</td></tr><tr><td>verifyClientID</td><td>false</td></tr><tr><td>authorizedClientIDs</td><td>nil</td></tr><tr><td>certBackdateDur</td><td>1 hours</td></tr><tr><td>certOffsetDur</td><td>1 hours</td></tr></tbody></table> | No       |                        |
| EnableRoleToken       | Use role token verification                                                                                        | true                                                                                                                                                                                                                                                                                                                  | No       | true                   |
| EnableRoleCert        | Use role cert verification                                                                                         | true                                                                                                                                                                                                                                                                                                                  | No       | true                   |

## License

```markdown
Copyright (C) 2018 Yahoo Japan Corporation Athenz team.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

## Contributor License Agreement

This project requires contributors to agree to a [Contributor License Agreement (CLA)](https://gist.github.com/ydnjp/3095832f100d5c3d2592).

Note that only for contributions to the `athenz-authorizer` repository on the [GitHub](https://github.com/yahoojapan/athenz-authorizer), the contributors of them shall be deemed to have agreed to the CLA without individual written agreements.

## About releases

- Releases
    - [![GitHub release (latest by date)](https://img.shields.io/github/v/release/yahoojapan/athenz-authorizer?style=flat-square&label=Github%20version)](https://github.com/yahoojapan/athenz-authorizer/releases/latest)

## Authors

- [kpango](https://github.com/kpango)
- [kevindiu](https://github.com/kevindiu)
- [TakuyaMatsu](https://github.com/TakuyaMatsu)
- [tatyano](https://github.com/tatyano)
- [WindzCUHK](https://github.com/WindzCUHK)
