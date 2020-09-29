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

type QueryValue struct {
	Value       string
	Placeholder string
}

type Rule struct {
	Method        string `yaml:"method"`
	Path          string `yaml:"path"`
	Action        string `yaml:"action"`
	Resource      string `yaml:"resource"`
	splitPaths    []SplitPath
	queryValueMap map[string]QueryValue
}

type MappingRules struct {
	Rules map[string][]Rule
}

func (mr *MappingRules) Translate(domain, method, path, query string) (string, string, error) {
	if mr.Rules == nil {
		err := mr.Validate()
		if err != nil {
			return "", "", err
		}
	}

OUTER:
	for _, rule := range mr.Rules[domain] {
		if rule.Method == method {
			requestedPaths := strings.Split(path[1:], "/")
			if len(requestedPaths) != len(rule.splitPaths) {
				continue
			}

			requestedQuery, err := url.ParseQuery(query)
			if err != nil {
				return "", "", err
			}
			if len(requestedQuery) != len(rule.queryValueMap) {
				continue
			}

			placeholderMap := make(map[string]string)
			for i, reqPath := range requestedPaths {
				if rule.splitPaths[i].Placeholder != "" {
					placeholderMap[rule.splitPaths[i].Placeholder] = reqPath
				} else if reqPath != rule.splitPaths[i].Path {
					continue OUTER
				}
			}

			for reqQuery, reqVal := range requestedQuery {
				if v, ok := rule.queryValueMap[reqQuery]; ok {
					if v.Placeholder != "" {
						placeholderMap[v.Placeholder] = reqVal[0]
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
	return method, path, nil
}

func (mr *MappingRules) Validate() error {
	for domain, rules := range mr.Rules {
		if domain == "" || rules == nil {
			return errors.New("k is empty or v is nil")
		}

		for i, r := range rules {
			if r.Method == "" || r.Path == "" || r.Action == "" || r.Resource == "" {
				return errors.New("Rule is empty")
			} else if !strings.HasPrefix(r.Path, "/") || r.Path == "/" {
				return errors.New("path is not started slash")
			}

			pathQuery := strings.Split(r.Path, "?")

			splitPaths := strings.Split(pathQuery[0][1:], "/")
			rules[i].splitPaths = make([]SplitPath, len(splitPaths))
			for j, p := range splitPaths {
				if ok := isPlaceholder(p); ok {
					rules[i].splitPaths[j] = SplitPath{Placeholder: p}
				} else {
					rules[i].splitPaths[j] = SplitPath{Path: p}
				}
			}

			rules[i].queryValueMap = make(map[string]QueryValue)
			if len(pathQuery) == 1 {
				continue
			}

			values, err := url.ParseQuery(pathQuery[1])
			if err != nil {
				return err
			}

			for q, v := range values {
				if len(v) != 1 {
					return errors.New("len(v) != 1")
				}
				if ok := isPlaceholder(v[0]); ok {
					rules[i].queryValueMap[q] = QueryValue{Placeholder: v[0]}
				} else {
					rules[i].queryValueMap[q] = QueryValue{Value: v[0]}
				}
			}
		}
	}
	return nil
}

func isPlaceholder(s string) bool {
	if strings.HasPrefix(s, placeholderPrefix) && strings.HasSuffix(s, placeholderSuffix) {
		return true
	} else {
		return false
	}
}
