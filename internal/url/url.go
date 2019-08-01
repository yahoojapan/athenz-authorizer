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

// Package url contains the utility functions for URL processing
package url

import (
	"regexp"
)

// TrimHTTPScheme check and trim the URL scheme
func TrimHTTPScheme(url string) (string, error) {
	re := regexp.MustCompile("^(http|https)://")
	s := re.ReplaceAllString(url, "")

	if regexp.MustCompile("^[A-Za-z]+://").MatchString(s) {
		return "", ErrUnsupportedScheme
	}

	return s, nil;
}
