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
	"fmt"
	"net/url"
	"strings"
)

const (
	placeholderPrefix = "{"
	placeholderSuffix = "}"
)

// Translator translates the information given to the argument to action and resource
type Translator interface {
	Translate(domain, method, path, query string) (string, string, error)
}

// param keeps information after it has been validated
type param struct {
	name          string
	isPlaceholder bool
}

// Rule represents a rule for translation
type Rule struct {
	Method        string `yaml:"method"`
	Path          string `yaml:"path"`
	Action        string `yaml:"action"`
	Resource      string `yaml:"resource"`
	splitPaths    []param
	queryValueMap map[string]param
}

// MappingRules keeps the translation rules
type MappingRules struct {
	Rules map[string][]Rule
}

// NewMappingRules creates the MappingRules object
func NewMappingRules(rules map[string][]Rule) (*MappingRules, error) {
	if rules == nil {
		return nil, errors.New("rules is nil")
	}
	mr := &MappingRules{Rules: rules}
	if err := mr.validate(); err != nil {
		return nil, err
	}
	return mr, nil
}

// Validate the given rule information
func (mr *MappingRules) validate() error {
	for domain, rules := range mr.Rules {
		if domain == "" {
			return errors.New("domain is empty")
		}
		if rules == nil {
			return errors.New("rules is nil")
		}

		for i, rule := range rules {
			if rule.Method == "" || rule.Action == "" || rule.Resource == "" {
				return fmt.Errorf("rule is empty, method:%s, action:%s, resource:%s",
					rule.Method, rule.Action, rule.Resource)
			}
			if rule.Path != "" && !strings.HasPrefix(rule.Path, "/") {
				return fmt.Errorf("path(%s) doesn't start with slash", rule.Path)
			}

			// For example, `rule.Path` assumes a string like `/path1/path2?param=value`
			pathQuery := strings.SplitN(rule.Path, "?", 2)

			splitPaths := strings.Split(pathQuery[0], "/")
			rules[i].splitPaths = make([]param, len(splitPaths))
			for j, path := range splitPaths {
				if ok, err := rules[i].isPlaceholder(path); ok {
					rules[i].splitPaths[j] = param{name: path, isPlaceholder: true}
				} else {
					if err != nil {
						return err
					}
					rules[i].splitPaths[j] = param{name: path, isPlaceholder: false}
				}
			}

			rules[i].queryValueMap = make(map[string]param)
			// No query parameter
			if len(pathQuery) == 1 {
				continue
			}

			values, err := url.ParseQuery(pathQuery[1])
			if err != nil {
				return err
			}

			for p, val := range values {
				if len(val) != 1 {
					return errors.New("query multiple values is not allowed")
				}
				if ok, err := rules[i].isPlaceholder(val[0]); ok {
					rules[i].queryValueMap[p] = param{name: val[0], isPlaceholder: true}
				} else {
					if err != nil {
						return err
					}
					rules[i].queryValueMap[p] = param{name: val[0], isPlaceholder: false}
				}
			}
		}
	}
	return nil
}

// Translate the information given to the argument to action and resource
func (mr *MappingRules) Translate(domain, method, path, query string) (string, string, error) {
	if mr.Rules == nil {
		return method, path, nil
	}

OUTER:
	for _, rule := range mr.Rules[domain] {
		if rule.Method == method {
			requestedPaths := strings.Split(path, "/")
			if len(requestedPaths) != len(rule.splitPaths) {
				continue
			}

			requestedQuery, err := url.ParseQuery(query)
			if err != nil {
				return method, path, err
			}
			if len(requestedQuery) != len(rule.queryValueMap) {
				continue
			}

			placeholderMap := make(map[string]string)
			for i, reqPath := range requestedPaths {
				if rule.splitPaths[i].isPlaceholder {
					placeholderMap[rule.splitPaths[i].name] = reqPath
				} else if reqPath != rule.splitPaths[i].name {
					continue OUTER
				}
			}

			for reqQuery, reqVal := range requestedQuery {
				// query multiple values is not allowed
				if len(reqVal) != 1 {
					continue OUTER
				}
				if v, ok := rule.queryValueMap[reqQuery]; ok {
					if v.isPlaceholder {
						placeholderMap[v.name] = reqVal[0]
					} else if reqVal[0] != v.name {
						continue OUTER
					}
				} else {
					continue OUTER
				}
			}

			replacedRes := rule.Resource
			for placeholder, v := range placeholderMap {
				replacedRes = strings.ReplaceAll(replacedRes, placeholder, v)
			}
			return rule.Action, replacedRes, nil
		}
	}
	return method, path, nil
}

func (r *Rule) isPlaceholder(s string) (bool, error) {
	if s == placeholderPrefix+placeholderSuffix {
		return false, errors.New("placeholder is empty")
	}

	if strings.HasPrefix(s, placeholderPrefix) && strings.HasSuffix(s, placeholderSuffix) {
		if r.splitPaths != nil {
			for _, p := range r.splitPaths {
				if p.isPlaceholder && p.name == s {
					return false, fmt.Errorf("placeholder(%s) is duplicated", s)
				}
			}
		}
		if r.queryValueMap != nil {
			for _, p := range r.queryValueMap {
				if p.isPlaceholder && p.name == s {
					return false, fmt.Errorf("placeholder(%s) is duplicated", s)
				}
			}
		}
		return true, nil
	}
	return false, nil
}
