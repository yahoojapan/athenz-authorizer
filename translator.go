/*
Copyright (C)  2020 Yahoo Japan Corporation Athenz team.

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

import (
	"errors"
	"net/url"
	"strings"
)

const (
	placeholderPrefix = "{"
	placeholderSuffix = "}"
)

type Translator interface {
	Translate(domain, method, path, query string) (string, string, error)
	Validate() error
}

type SplitPath struct {
	Path        string
	Placeholder string
}

type Rule struct {
	Method     string `yaml:"method"`
	Path       string `yaml:"path"`
	Action     string `yaml:"action"`
	Resource   string `yaml:"resource"`
	splitPaths []SplitPath
	splitQuery url.Values
}

type MappingRules struct {
	Rules map[string][]Rule
}

func (mr *MappingRules) Translate(domain, method, path, query string) (string, string, error) {
OUTER:
	for _, rule := range mr.Rules[domain] {
		if rule.Method == method {
			requestedPaths := strings.Split(path, "/")
			requestedQuery, err := url.ParseQuery(query)
			if err != nil {
				// break
				return "", "", err
			}

			if len(requestedPaths) == len(rule.splitPaths) &&
				len(requestedQuery) == len(rule.splitQuery) {

				placeholderMap := make(map[string]string)
				for i, reqPath := range requestedPaths {
					if rule.splitPaths[i].Placeholder != "" {
						placeholderMap[rule.splitPaths[i].Placeholder] = reqPath
					} else if reqPath != rule.splitPaths[i].Path {
						continue OUTER
					}
				}

				for reqQuery, reqVal := range requestedQuery {
					if len(reqVal) != 1 {
						// break
						return "", "", errors.New("len(reqVal) != 1")
					}
					if v, ok := rule.splitQuery[reqQuery]; ok {
						if b, placeholder := isPlaceholder(v[0]); b {
							placeholderMap[placeholder] = reqVal[0]
						} else if reqVal[0] != v[0] {
							continue OUTER
						}
					} else {
						continue OUTER
					}
				}

				replacedRes := rule.Resource
				for placeholder, v := range placeholderMap {
					replacedRes = strings.Replace(replacedRes, placeholder, v, 1)
				}
				return rule.Action, replacedRes, nil
			}
		}
	}
	return method, path, nil
}

func (mr *MappingRules) Validate() error {
	for _, v := range mr.Rules {
		for _, r := range v {
			pathQuery := strings.Split(r.Path, "?")

			splitPaths := strings.Split(pathQuery[0], "/")
			r.splitPaths = make([]SplitPath, len(splitPaths))
			for i, s := range splitPaths {
				if b, placeholder := isPlaceholder(s); b {
					r.splitPaths[i] = SplitPath{Placeholder: placeholder}
				} else {
					r.splitPaths[i] = SplitPath{Path: s}
				}
			}

			var err error
			r.splitQuery, err = url.ParseQuery(pathQuery[1])
			if err != nil {
				return err
			}
			for _, v := range r.splitQuery {
				if len(v) != 1 {
					return errors.New("len(v) != 1")
				}
				if b, placeholder := isPlaceholder(v[0]); b {
					for _, s := range r.splitPaths {
						if placeholder == s.Placeholder {
							return errors.New("placeholder duplicated")
						}
					}
				}
			}
		}
	}
	return nil
}

func isPlaceholder(s string) (bool, string) {
	if strings.HasPrefix(s, placeholderPrefix) && strings.HasSuffix(s, placeholderSuffix) {
		s = strings.TrimPrefix(s, placeholderPrefix)
		s = strings.TrimSuffix(s, placeholderSuffix)
		return true, s
	} else {
		return false, s
	}
}
