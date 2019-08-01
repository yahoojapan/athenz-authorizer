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
	"sync"
)

var (
	httpReg    *regexp.Regexp
	schemeReg  *regexp.Regexp
	httpOnce   = sync.Once{}
	schemeOnce = sync.Once{}
)

// TrimHTTPScheme check and trim the URL scheme
func TrimHTTPScheme(url string) string {
	httpOnce.Do(func() {
		httpReg = regexp.MustCompile("^(http|https)://")
	})

	return httpReg.ReplaceAllString(url, "")
}

// HasScheme check if url has any scheme
func HasScheme(url string) bool {
	schemeOnce.Do(func() {
		schemeReg = regexp.MustCompile("^[a-zA-Z][a-zA-Z0-9+-.]*://")
	})

	return schemeReg.MatchString(url)
}
