package url

import (
	"errors"
)

// ErrUnsupportedScheme is "Unsupported scheme, only support HTTP or HTTPS"
var ErrUnsupportedScheme = errors.New("Unsupported scheme, only support HTTP or HTTPS")
