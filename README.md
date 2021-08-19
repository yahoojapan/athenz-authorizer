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

- [What is Athenz authorizer](#what-is-athenz-authorizer)
- [Usage](#usage)
- [How it works](#how-it-works)
    - [Athenz public key daemon](#athenz-public-key-daemon)
    - [Athenz policy daemon](#athenz-policy-daemon)
- [Configuration](#configuration)
    - [AccessTokenParam](#accesstokenparam)
- [License](#license)
- [Contributor License Agreement](#contributor-license-agreement)
- [About releases](#about-releases)
- [Authors](#authors)

<!-- /TOC -->

## What is Athenz authorizer

Athenz authorizer is a library to cache the policies of [Athenz](https://github.com/AthenZ/athenz) to authorizer authentication and authorization check of user request.

![Overview](./docs/assets/policy_updater_overview.png)

## Usage

To initialize authorizer.

```golang
// Initialize authorizerd
daemon, err := authorizerd.New(
    authorizerd.WithAthenzURL("www.athenz.io"), // set athenz URL
    authorizerd.WithAthenzDomains("domain1", "domain2" ... "domain N"), // set athenz domains
    authorizerd.WithPubkeyRefreshPeriod("24h"), // set athenz public key refresh period
    authorizerd.WithPolicyRefreshPeriod("1h"), // set policy refresh period
)
if err != nil {
   // cannot initialize authorizer daemon
}

// Start authorizer daemon
ctx := context.Background() // user can control authorizer daemon lifetime using this context
if err = daemon.Init(ctx); err != nil {
    // cannot initialize internal daemon inside authorizer
}
errs := daemon.Start(ctx)
go func() {
    err := <-errs
    // user should handle errors return from the daemon
}()

// Verify role token
if err := daemon.VerifyRoleToken(ctx, roleTok, act, res); err != nil {
    // token not authorized
}

// Verified results are returned
principal, err := daemon.AuthorizeRoleToken(ctx, roleTok, act, res)
if err != nil {
    // token not authorized
}
// Inspect the authorized identity
name := principal.Name()
```

## How it works

To do the authentication and authorization check, the user needs to specify which [domain data](https://github.com/AthenZ/athenz/blob/master/docs/data_model.md#data-model) to be cache. The authorizer will periodically refresh the policies and Athenz public key data to [verify and decode](https://github.com/AthenZ/athenz/blob/master/docs/zpu_policy_file.md#zts-signature-validation) the domain data. The verified domain data will cache into the memory, and use for authentication and authorization check.

The authorizer contains two sub-module, Athenz public key daemon (pubkeyd) and Athenz policy daemon (policyd).

### Athenz public key daemon

Athenz public key daemon (pubkeyd) is responsible for periodically update the Athenz public key data from Athenz server to verify the policy data received from Athenz policy daemon and verify the role token.

### Athenz policy daemon

Athenz policy daemon (policyd) is responsible for periodically update the policy data of specified Athenz domain from Athenz server. The received policy data will be verified using the public key got from pubkeyd, and cache into memory. Whenever user requesting for the access check, the verification check will be used instead of asking Athenz server every time.

## Configuration

The authorizer uses functional options pattern to initialize the instance. All the options are defined [here](./option.go).

| Option name             | Description                                                                   | Default Value                                 | Required | Example                                      |
| ----------------------- | ----------------------------------------------------------------------------- | --------------------------------------------- | -------- | -------------------------------------------- |
| AthenzURL               | The Athenz server URL                                                         | athenz\.io/zts/v1                             | Yes      | "athenz\.io/zts/v1"                          |
| AthenzDomains           | Athenz domain names that contain the RBAC policies                            | \[\]                                          | Yes      | "domName1", "domName2"                       |
| HTTPClient              | The HTTP client for connecting to Athenz server                               | http\.Client\{ Timeout: 30 \* time\.Second \} | No       | http\.DefaultClient                          |
| CacheExp                | The TTL of the success cache                                                  | 1 Minute                                      | No       | 1 \* time\.Minute                            |
| Enable/DisablePubkeyd   | Run public key daemon or not                                                  | true                                          | No       |                                              |
| PubkeySysAuthDomain     | System authority domain name to retrieve Athenz public key data               | sys\.auth                                     | No       | "sys.auth"                                   |
| PubkeyRefreshPeriod     | Period to refresh the Athenz public key data                                  | 24 Hours                                      | No       | "24h"                                        |
| PubkeyETagExpiry        | ETag cache TTL of Athenz public key data                                      | 168 Hours \(1 Week\)                          | No       | "168h"                                       |
| PubkeyETagPurgePeriod   | ETag cache purge duration                                                     | 84 Hours                                      | No       | "84h"                                        |
| PubkeyRetryDelay        | Delay of next retry on request failed                                         | 1 Minute                                      | No       | "1m"                                         |
| Enable/DisablePolicyd   | Run policy daemon or not                                                      | true                                          | No       |                                              |
| PolicyExpiryMargin      | Update the policy by a margin duration before the policy actually expires     | 3 Hours                                       | No       | "3h"                                         |
| PolicyRefreshPeriod     | Period to refresh the Athenz policies                                         | 30 Minutes                                    | No       | "30m"                                        |
| PolicyPurgePeriod       | Policy cache purge duration                                                   | 1 Hours                                       | No       | "1h"                                         |
| PolicyRetryDelay        | Delay of next retry on request fail                                           | 1 Minute                                      | No       | "1m"                                         |
| PolicyRetryAttempts     | Maximum retry attempts on request fail                                        | 2                                             | No       | 2                                            |
| Enable/DisableJwkd      | Run JWK daemon or not                                                         | true                                          | No       |                                              |
| JwkRefreshPeriod        | Period to refresh the Athenz JWK                                              | 24 Hours                                      | No       | "24h"                                        |
| JwkRetryDelay           | Delay of next retry on request fail                                           | 1 Minute                                      | No       | "1m"                                         |
| jwkURLs                 | URL to get jwk other than  AthenzURL                                          | []                                            | No       | "http://domain1/jwks", "http://domain2/jwks" |
| AccessTokenParam        | Use access token verification, details: [AccessTokenParam](#accesstokenparam) | Same as [AccessTokenParam](#accesstokenparam) | No       | \{\}                                         |
| Enable/DisableRoleToken | Use role token verification or not                                            | true                                          | No       |                                              |
| RoleAuthHeader          | The HTTP header to extract role token                                         | Athenz\-Role\-Auth                            | No       | "Athenz\-Role\-Auth"                         |
| Enable/DisableRoleCert  | Use role certificate verification or not                                      | true                                          | No       |                                              |
| RoleCertURIPrefix       | Extract role from role certificate                                            | athenz://role/                                | No       | "athenz://role/"                             |

### AccessTokenParam

| **Option name**      | **Description**                                                                | **Default Value** | **Required** | **Example**                                    |
| -------------------- | ------------------------------------------------------------------------------ | ----------------- | ------------ | ---------------------------------------------- |
| enable               | Use access token verification or not                                           | true              | No           | true                                           |
| verifyCertThumbprint | Use certificate bound access token verification                                | true              | No           | true                                           |
| certBackdateDur      | Backdate duration of the issue time of the certificate                         | 1 Hour            | No           | "1h"                                           |
| certOffsetDur        | Offset window to accept access token with a mismatching certificate thumbprint | 1 Hour            | No           | "1h"                                           |
| verifyClientID       | Use authorized client ID verification                                          | false             | No           | false                                          |
| authorizedClientIDs  | Authorized client ID to certificate common name map                            | nil               | No           | \{ "atClientID": \{ "certCN1", "certCN2" \} \} |

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
