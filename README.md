# Athenz policy updater

## What is Athenz policy updater

Athenz policy updater is a library to cache the policies of [Athenz](https://github.com/yahoo/athenz) to provider authenication and authorization check of user request.

## Usage

To initialize policy updater.

```go

athenzURL := "www.athenz.io" // athenz URL
athenzDoms := []string { // athenz Domains
    "dom1",
    "dom2",
}
confRefreshDur := time.Hour * 24 // athenzConf refresh duration
polRefreshDur := time.Hour // policy refresh duration

func Main() {
    // Initialize providerd
    daemon, err := New()
    if err != nil {
       // cannot initialize providerd
    }

    // Start providerd 
    ctx := context.Background() // user can control providerd daemon lifetime using this context
    errs := daemon.StartProviderd(ctx)
    go func() {
        err := <-errs
        // user should handle errors return from providerd
    }()

    // Verify role token
    if err := daemon.VerifyRoleToken(ctx, roleTok, act, res); err != nil {
        // token not authorizated
    }
}

func New() (providerd.Providerd, error) {
    return providerd.New(
        providerd.AthenzURL(athenzURL),
        providerd.AthenzDomains(athenzDoms),
        providerd.AthenzConfRefreshDuration(confRefreshDur),
        providerd.PolicyRefreshDuration(polRefreshDur),
    )
}
```

## License

```markdown
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
```

## Contributor License Agreement

This project requires contributors to agree to a [Contributor License Agreement (CLA)](https://gist.github.com/ydnjp/3095832f100d5c3d2592).

Note that only for contributions to the garm repository on the [GitHub](https://github.com/yahoojapan/garm), the contributors of them shall be deemed to have agreed to the CLA without individual written agreements.

## Authors

- [kpango](https://github.com/kpango)
- [kevindiu](https://github.com/kevindiu)
- [TakuyaMatsu](https://github.com/TakuyaMatsu)
- [tatyano](https://github.com/tatyano)
