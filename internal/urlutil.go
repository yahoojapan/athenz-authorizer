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

// Package urlutil contains the utility functions for URL processing
package urlutil

import (
	"errors"
	"net/url"
)

var (
	// ErrUnsupportedScheme is "Unsupported scheme, only support HTTP or HTTPS"
	ErrUnsupportedScheme = errors.New("Unsupported scheme, only support HTTP or HTTPS")
)

// TrimHTTPScheme check and trim the URL scheme
func TrimHTTPScheme(urlStr string) (string, error) {
	url, err := url.Parse(urlStr)
	if err != nil {
		return "", err
	}

	// check scheme
	scheme := url.Scheme
	if scheme != "" {
		if scheme != "http" && scheme != "https" {
			return "", ErrUnsupportedScheme
		}
	}

	// trim scheme, and remove '//' prefix
	url.Scheme = ""
	if url.Host == "" {
		return url.String(), nil
	}
	return url.String()[2:], nil

}
