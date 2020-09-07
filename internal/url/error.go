package url

import (
	"errors"
)

// ErrEmptyAthenzURL is "Athenz URL is empty"
var ErrEmptyAthenzURL = errors.New("Athenz URL is empty")

// ErrUnsupportedScheme is "Unsupported scheme, only support HTTP or HTTPS"
var ErrUnsupportedScheme = errors.New("Unsupported scheme, only support HTTP or HTTPS")
