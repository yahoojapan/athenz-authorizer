package url

import (
	"errors"
)

// ErrEmptyAthenzJwksURL is "Athenz URL is empty"
var ErrEmptyAthenzJwksURL = errors.New("Athenz JKU is empty")

// ErrUnsupportedScheme is "Unsupported scheme, only support HTTP or HTTPS"
var ErrUnsupportedScheme = errors.New("Unsupported scheme, only support HTTP or HTTPS")
