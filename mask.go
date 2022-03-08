/*
Copyright (C)  2022 Yahoo Japan Corporation Athenz team.

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

package authorizerd

import "strings"

func maskCacheKey(key, tok string) string {
	return key[len(tok):]
}

func maskToken(m mode, tok string) string {
	switch m {
	case roleToken:
		i := strings.Index(tok, ";s=")
		if i > 0 {
			return tok[:i]
		}
		return "mask token error: invalid role token"
	case accessToken:
		i := strings.LastIndex(tok, ".")
		if i > 0 {
			return tok[:i]
		}
		return "mask token error: invalid access token"
	default:
		return "mask token error: unknown token"
	}
}
