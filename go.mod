module github.com/yahoojapan/athenz-authorizer/v5

go 1.16

require (
	github.com/AthenZ/athenz v1.10.48
	github.com/ardielle/ardielle-go v1.5.2
	github.com/golang-jwt/jwt/v4 v4.3.0
	github.com/google/go-cmp v0.5.7
	github.com/kpango/fastime v1.1.4
	github.com/kpango/gache v1.2.7
	github.com/kpango/glg v1.6.10
	github.com/lestrrat-go/jwx v1.2.20
	github.com/pkg/errors v0.9.1
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
)

replace (
	golang.org/x/text v0.3.0 => golang.org/x/text v0.3.3
	golang.org/x/text v0.3.2 => golang.org/x/text v0.3.3
)
