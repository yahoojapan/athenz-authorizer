module github.com/yahoojapan/athenz-authorizer/v5

go 1.14

require (
	github.com/AthenZ/athenz v1.10.28
	github.com/ardielle/ardielle-go v1.5.2
	github.com/golang-jwt/jwt v3.2.1+incompatible
	github.com/google/go-cmp v0.5.6
	github.com/kpango/fastime v1.0.17
	github.com/kpango/gache v1.2.6
	github.com/kpango/glg v1.6.4
	github.com/lestrrat-go/jwx v1.0.8
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.7.0
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
)

replace (
	golang.org/x/text v0.3.0 => golang.org/x/text v0.3.3
	golang.org/x/text v0.3.2 => golang.org/x/text v0.3.3
)
