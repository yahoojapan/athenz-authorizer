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
	"fmt"
	"reflect"
	"testing"
)

func TestRule_isPlaceholder(t *testing.T) {
	tests := []struct {
		name       string
		rule       Rule
		arg        string
		wantResult bool
		wantErrStr string
	}{
		{
			name: "success",
			rule: Rule{
				splitPaths:    []param{},
				queryValueMap: map[string]param{},
			},
			arg:        "{placeholder}",
			wantResult: true,
		},
		{
			name: "placeholder is empty",
			rule: Rule{
				splitPaths:    []param{},
				queryValueMap: map[string]param{},
			},
			arg:        "{}",
			wantResult: false,
			wantErrStr: "placeholder is empty",
		},
		{
			name: "not placeholder",
			rule: Rule{
				splitPaths:    []param{},
				queryValueMap: map[string]param{},
			},
			arg:        "{placeholder",
			wantResult: false,
		},
		{
			name: "not placeholder",
			rule: Rule{
				splitPaths:    []param{},
				queryValueMap: map[string]param{},
			},
			arg:        "placeholder}",
			wantResult: false,
		},
		{
			name: "not placeholder",
			rule: Rule{
				splitPaths:    []param{},
				queryValueMap: map[string]param{},
			},
			arg:        "",
			wantResult: false,
		},
		{
			name: "placeholder is duplicated",
			rule: Rule{
				splitPaths: []param{{
					name:          "{placeholder}",
					isPlaceholder: true,
				}},
				queryValueMap: map[string]param{},
			},
			arg:        "{placeholder}",
			wantResult: false,
			wantErrStr: fmt.Sprintf("placeholder(%s) is duplicated", "{placeholder}"),
		},
		{
			name: "placeholder is duplicated",
			rule: Rule{
				splitPaths: []param{},
				queryValueMap: map[string]param{"": {
					name:          "{placeholder}",
					isPlaceholder: true,
				}},
			},
			arg:        "{placeholder}",
			wantResult: false,
			wantErrStr: fmt.Sprintf("placeholder(%s) is duplicated", "{placeholder}"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := tt.rule.isPlaceholder(tt.arg)

			if err != nil {
				if tt.wantErrStr == "" {
					t.Errorf("wantErrStr is empty, but err is %s", err.Error())
					return
				} else if err.Error() != tt.wantErrStr {
					t.Errorf("err(%s) and wantErrStr(%s) are not the same", err.Error(), tt.wantErrStr)
					return
				} else if r != tt.wantResult {
					t.Errorf("Expectation was an %t, but it was actually a %t", tt.wantResult, r)
					return
				} else {
					return
				}
			} else {
				if tt.wantErrStr != "" {
					t.Errorf("err is nil, but wantErrStr is %s", tt.wantErrStr)
					return
				} else {
					if r != tt.wantResult {
						t.Errorf("Expectation was an %t, but it was actually a %t", tt.wantResult, r)
						return
					} else {
						return
					}
				}
			}
		})
	}
}

func TestNewMappingRules(t *testing.T) {
	tests := []struct {
		name         string
		mappingRules map[string][]Rule
		want         *MappingRules
		wantErrStr   string
	}{
		{
			name: "success",
			mappingRules: map[string][]Rule{
				"domain": {Rule{
					Method:   "get",
					Path:     "/path?param=value",
					Action:   "read",
					Resource: "resource",
				}},
			},
			want: &MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Path:     "/path?param=value",
						Action:   "read",
						Resource: "resource",
						splitPaths: []param{
							{
								name: "",
							},
							{
								name: "path",
							},
						},
						queryValueMap: map[string]param{
							"param": {
								name: "value",
							},
						},
					},
				},
			}},
		},
		{
			name:         "error rules is nil",
			mappingRules: nil,
			wantErrStr:   "rules is nil",
		},
		{
			name: "error validate function returns an error",
			mappingRules: map[string][]Rule{
				"": {},
			},
			wantErrStr: "domain is empty",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mr, err := NewMappingRules(tt.mappingRules)

			if err != nil {
				if tt.wantErrStr == "" {
					t.Errorf("wantErrStr is empty, but err is %s", err.Error())
					return
				} else if err.Error() != tt.wantErrStr {
					t.Errorf("err(%s) and wantErrStr(%s) are not the same", err.Error(), tt.wantErrStr)
					return
				} else {
					return
				}
			} else {
				if tt.wantErrStr != "" {
					t.Errorf("err is nil, but wantErrStr is %s", tt.wantErrStr)
					return
				}
			}
			// {map[domain:[{get /path?param=value read resource [{ false} {path false}] map[param:{value false}]}]]}
			//
			if !reflect.DeepEqual(mr, tt.want) {
				t.Errorf("expectation was %v, but it was actually %v", tt.want, mr)
				return
			}
		})
	}
}

func TestMappingRules_validate(t *testing.T) {
	tests := []struct {
		name             string
		mappingRules     map[string][]Rule
		wantMappingRules MappingRules
		wantErrStr       string
	}{
		{
			name: "success path only",
			mappingRules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Path:     "/path1/path2/path3",
						Action:   "read",
						Resource: "resource",
					},
				},
			},
			wantMappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						splitPaths: []param{
							{
								name: "",
							},
							{
								name: "path1",
							},
							{
								name: "path2",
							},
							{
								name: "path3",
							},
						},
						queryValueMap: map[string]param{},
					},
				},
			}},
		},
		{
			name: "success path is empty",
			mappingRules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Path:     "",
						Action:   "read",
						Resource: "resource",
					},
				},
			},
			wantMappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						splitPaths: []param{
							{
								name: "",
							},
						},
						queryValueMap: map[string]param{},
					},
				},
			}},
		},
		{
			name: "success path is slash",
			mappingRules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Path:     "/",
						Action:   "read",
						Resource: "resource",
					},
				},
			},
			wantMappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						splitPaths: []param{
							{
								name: "",
							},
							{
								name: "",
							},
						},
						queryValueMap: map[string]param{},
					},
				},
			}},
		},
		{
			name: "success continuous slashes",
			mappingRules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Path:     "/path1//path2/",
						Action:   "read",
						Resource: "resource",
					},
				},
			},
			wantMappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						splitPaths: []param{
							{
								name: "",
							},
							{
								name: "path1",
							},
							{
								name: "",
							},
							{
								name: "path2",
							},
							{
								name: "",
							},
						},
						queryValueMap: map[string]param{},
					},
				},
			}},
		},
		{
			name: "success path with placeholder",
			mappingRules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Path:     "/path1/{placeholder1}/path2/{placeholder2}",
						Action:   "read",
						Resource: "resource",
					},
				},
			},
			wantMappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						splitPaths: []param{
							{
								name: "",
							},
							{
								name: "path1",
							},
							{
								name:          "{placeholder1}",
								isPlaceholder: true,
							},
							{
								name: "path2",
							},
							{
								name:          "{placeholder2}",
								isPlaceholder: true,
							},
						},
						queryValueMap: map[string]param{},
					},
				},
			}},
		},
		{
			name: "error path placeholder is empty",
			mappingRules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Path:     "/path1/{}",
						Action:   "read",
						Resource: "resource",
					},
				},
			},
			wantErrStr: "placeholder is empty",
		},
		{
			name: "success path and query",
			mappingRules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Path:     "/path1/path2?param1=value1&param2=value2",
						Action:   "read",
						Resource: "resource",
					},
				},
			},
			wantMappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						splitPaths: []param{
							{
								name: "",
							},
							{
								name: "path1",
							},
							{
								name: "path2",
							},
						},
						queryValueMap: map[string]param{
							"param1": {
								name: "value1",
							},
							"param2": {
								name: "value2",
							},
						},
					},
				},
			}},
		},
		{
			name: "success a question mark in the query.",
			mappingRules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Path:     "/path1?param1=value1?&param2=value2",
						Action:   "read",
						Resource: "resource",
					},
				},
			},
			wantMappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						splitPaths: []param{
							{
								name: "",
							},
							{
								name: "path1",
							},
						},
						queryValueMap: map[string]param{
							"param1": {
								name: "value1?",
							},
							"param2": {
								name: "value2",
							},
						},
					},
				},
			}},
		},
		{
			name: "success path with placeholder and query with placeholder",
			mappingRules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Path:     "/path1/{path2}?param1=value1&param2={value2}",
						Action:   "read",
						Resource: "resource",
					},
				},
			},
			wantMappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						splitPaths: []param{
							{
								name: "",
							},
							{
								name: "path1",
							},
							{
								name:          "{path2}",
								isPlaceholder: true,
							},
						},
						queryValueMap: map[string]param{
							"param1": {
								name: "value1",
							},
							"param2": {
								name:          "{value2}",
								isPlaceholder: true,
							},
						},
					},
				},
			}},
		},
		{
			name: "error query placeholder is empty",
			mappingRules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Path:     "/path1?param1=value1&param2={}",
						Action:   "read",
						Resource: "resource",
					},
				},
			},
			wantErrStr: "placeholder is empty",
		},
		{
			name: "error query multiple values",
			mappingRules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Path:     "/path1?param1=value1&param1=value2",
						Action:   "read",
						Resource: "resource",
					},
				},
			},
			wantErrStr: "query multiple values is not allowed",
		},
		{
			name: "error domain is empty",
			mappingRules: map[string][]Rule{
				"": {
					Rule{
						Method:   "method",
						Path:     "/path",
						Action:   "read",
						Resource: "resource",
					},
				},
			},
			wantErrStr: "domain is empty",
		},
		{
			name: "error rules is empty",
			mappingRules: map[string][]Rule{
				"domain": nil,
			},
			wantErrStr: "rules is nil",
		},
		{
			name: "error method is empty",
			mappingRules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "",
						Path:     "/path",
						Action:   "read",
						Resource: "resource",
					},
				},
			},
			wantErrStr: fmt.Sprintf("rule is empty, method:%s, action:%s, resource:%s", "", "read", "resource"),
		},
		{
			name: "error action is empty",
			mappingRules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Path:     "/path",
						Action:   "",
						Resource: "resource",
					},
				},
			},
			wantErrStr: fmt.Sprintf("rule is empty, method:%s, action:%s, resource:%s", "get", "", "resource"),
		},
		{
			name: "error resource is empty",
			mappingRules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Path:     "/path",
						Action:   "read",
						Resource: "",
					},
				},
			},
			wantErrStr: fmt.Sprintf("rule is empty, method:%s, action:%s, resource:%s", "get", "read", ""),
		},
		{
			name: "error path has no slash",
			mappingRules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Path:     "path",
						Action:   "read",
						Resource: "resource",
					},
				},
			},
			wantErrStr: fmt.Sprintf("path(%s) doesn't start with slash", "path"),
		},
		{
			name: "error duplicated path placeholder",
			mappingRules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Path:     "/path1/{placeholder1}/{placeholder1}",
						Action:   "read",
						Resource: "resource",
					},
				},
			},
			wantErrStr: fmt.Sprintf("placeholder(%s) is duplicated", "{placeholder1}"),
		},
		{
			name: "error duplicated path and query placeholder",
			mappingRules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Path:     "/path1/{placeholder1}?param1={placeholder1}",
						Action:   "read",
						Resource: "resource",
					},
				},
			},
			wantErrStr: fmt.Sprintf("placeholder(%s) is duplicated", "{placeholder1}"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mr := MappingRules{tt.mappingRules}
			err := mr.validate()
			if err != nil {
				if tt.wantErrStr == "" {
					t.Errorf("wantErrStr is empty, but err is %s", err.Error())
					return
				} else if err.Error() != tt.wantErrStr {
					t.Errorf("err(%s) and wantErrStr(%s) are not the same", err.Error(), tt.wantErrStr)
					return
				} else {
					return
				}
			} else {
				if tt.wantErrStr != "" {
					t.Errorf("err is nil, but wantErrStr is %s", tt.wantErrStr)
					return
				}
			}

			for domain, rules := range mr.Rules {
				for i, rule := range rules {
					wantRules, ok := tt.wantMappingRules.Rules[domain]
					if !ok {
						t.Errorf("wantMappingRules doesn't have domain(%s)", domain)
						return
					}
					if !reflect.DeepEqual(rule.splitPaths, wantRules[i].splitPaths) ||
						!reflect.DeepEqual(rule.queryValueMap, wantRules[i].queryValueMap) {
						t.Errorf("wantMappingRules is not an expectaion")
						return
					}
				}
			}
		})
	}
}

func TestMappingRules_Translate(t *testing.T) {
	tests := []struct {
		name         string
		mappingRules MappingRules
		domain       string
		method       string
		path         string
		query        string
		wantAction   string
		wantResource string
	}{
		{
			name: "path matches",
			mappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Action:   "read",
						Resource: "resource",
						splitPaths: []param{
							{
								name: "",
							},
							{
								name: "path1",
							},
							{
								name: "path2",
							},
						},
						queryValueMap: map[string]param{},
					},
				},
			}},
			domain:       "domain",
			method:       "get",
			path:         "/path1/path2",
			query:        "",
			wantAction:   "read",
			wantResource: "resource",
		},
		{
			name: "slash path matches",
			mappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Action:   "read",
						Resource: "resource",
						splitPaths: []param{
							{
								name: "",
							},
							{
								name: "",
							},
						},
						queryValueMap: map[string]param{},
					},
				},
			}},
			domain:       "domain",
			method:       "get",
			path:         "/",
			query:        "",
			wantAction:   "read",
			wantResource: "resource",
		},
		{
			name: "empty path matches",
			mappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Action:   "read",
						Resource: "resource",
						splitPaths: []param{
							{
								name: "",
							},
						},
						queryValueMap: map[string]param{},
					},
				},
			}},
			domain:       "domain",
			method:       "get",
			path:         "",
			query:        "",
			wantAction:   "read",
			wantResource: "resource",
		},
		{
			name: "domain didn't match",
			mappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Action:   "read",
						Resource: "resource",
						splitPaths: []param{
							{
								name: "",
							},
							{
								name: "path1",
							},
							{
								name: "path2",
							},
						},
						queryValueMap: map[string]param{},
					},
				},
			}},
			domain:       "domain1",
			method:       "get",
			path:         "/path1/path2",
			query:        "",
			wantAction:   "get",
			wantResource: "/path1/path2",
		},
		{
			name: "method didn't matches",
			mappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Action:   "read",
						Resource: "resource",
						splitPaths: []param{
							{
								name: "",
							},
							{
								name: "path1",
							},
							{
								name: "path2",
							},
						},
						queryValueMap: map[string]param{},
					},
				},
			}},
			domain:       "domain",
			method:       "post",
			path:         "/path1/path2",
			query:        "",
			wantAction:   "post",
			wantResource: "/path1/path2",
		},
		{
			name:         "rules is nil",
			mappingRules: MappingRules{Rules: nil},
			domain:       "domain",
			method:       "get",
			path:         "/path1/path2",
			query:        "",
			wantAction:   "get",
			wantResource: "/path1/path2",
		},
		{
			name: "path with placeholder matches",
			mappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Action:   "read",
						Resource: "resource.{placeholder1}",
						splitPaths: []param{
							{
								name: "",
							},
							{
								name: "path1",
							},
							{
								name:          "{placeholder1}",
								isPlaceholder: true,
							},
							{
								name: "path3",
							},
						},
						queryValueMap: map[string]param{},
					},
				},
			}},
			domain:       "domain",
			method:       "get",
			path:         "/path1/path2/path3",
			query:        "",
			wantAction:   "read",
			wantResource: "resource.path2",
		},
		{
			name: "path with two placeholders matches",
			mappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Action:   "read",
						Resource: "resource.{placeholder1}.{placeholder2}",
						splitPaths: []param{
							{
								name: "",
							},
							{
								name:          "{placeholder1}",
								isPlaceholder: true,
							},
							{
								name:          "{placeholder2}",
								isPlaceholder: true,
							},
						},
						queryValueMap: map[string]param{},
					},
				},
			}},
			domain:       "domain",
			method:       "get",
			path:         "/path1/path2",
			query:        "",
			wantAction:   "read",
			wantResource: "resource.path1.path2",
		},
		{
			name: "multiple placeholders in a resource",
			mappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Action:   "read",
						Resource: "resource.{placeholder1}.{placeholder1}.{placeholder1}",
						splitPaths: []param{
							{
								name: "",
							},
							{
								name: "path1",
							},
							{
								name:          "{placeholder1}",
								isPlaceholder: true,
							},
							{
								name: "path3",
							},
						},
						queryValueMap: map[string]param{},
					},
				},
			}},
			domain:       "domain",
			method:       "get",
			path:         "/path1/path2/path3",
			query:        "",
			wantAction:   "read",
			wantResource: "resource.path2.path2.path2",
		},
		{
			name: "path and query with placeholder matches",
			mappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Action:   "read",
						Resource: "resource.{placeholder1}.{placeholder2}",
						splitPaths: []param{
							{
								name: "",
							},
							{
								name: "path1",
							},
							{
								name:          "{placeholder1}",
								isPlaceholder: true,
							},
						},
						queryValueMap: map[string]param{
							"param1": {
								name: "value1",
							},
							"param2": {
								name:          "{placeholder2}",
								isPlaceholder: true,
							},
						},
					},
				},
			}},
			domain:       "domain",
			method:       "get",
			path:         "/path1/path2",
			query:        "param2=value2&param1=value1",
			wantAction:   "read",
			wantResource: "resource.path2.value2",
		},
		{
			name: "path and query with two placeholders matches",
			mappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Action:   "read",
						Resource: "resource.{placeholder1}.{placeholder2}.{placeholder3}",
						splitPaths: []param{
							{
								name: "",
							},
							{
								name: "path1",
							},
							{
								name:          "{placeholder1}",
								isPlaceholder: true,
							},
						},
						queryValueMap: map[string]param{
							"param1": {
								name:          "{placeholder2}",
								isPlaceholder: true,
							},
							"param2": {
								name:          "{placeholder3}",
								isPlaceholder: true,
							},
						},
					},
				},
			}},
			domain:       "domain",
			method:       "get",
			path:         "/path1/path2",
			query:        "param2=value2&param1=value1",
			wantAction:   "read",
			wantResource: "resource.path2.value1.value2",
		},
		{
			name: "the path lengths are not equal",
			mappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Action:   "read",
						Resource: "resource",
						splitPaths: []param{
							{
								name: "",
							},
							{
								name: "path1",
							},
							{
								name:          "{placeholder1}",
								isPlaceholder: true,
							},
						},
						queryValueMap: map[string]param{},
					},
				},
			}},
			domain:       "domain",
			method:       "get",
			path:         "/path1",
			query:        "",
			wantAction:   "get",
			wantResource: "/path1",
		},
		{
			name: "path didn't match",
			mappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Action:   "read",
						Resource: "resource",
						splitPaths: []param{
							{
								name: "",
							},
							{
								name:          "{placeholder1}",
								isPlaceholder: true,
							},
							{
								name: "path3",
							},
						},
						queryValueMap: map[string]param{},
					},
				},
			}},
			domain:       "domain",
			method:       "get",
			path:         "/path1/path2",
			query:        "",
			wantAction:   "get",
			wantResource: "/path1/path2",
		},
		{
			name: "the query lengths are not equal",
			mappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Action:   "read",
						Resource: "resource",
						splitPaths: []param{
							{
								name: "",
							},
							{
								name: "path1",
							},
						},
						queryValueMap: map[string]param{
							"param1": {
								name: "value1",
							},
							"param2": {
								name:          "{placeholder2}",
								isPlaceholder: true,
							},
						},
					},
				},
			}},
			domain:       "domain",
			method:       "get",
			path:         "/path1",
			query:        "param1=value1",
			wantAction:   "get",
			wantResource: "/path1",
		},
		{
			name: "query multiple values",
			mappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Action:   "read",
						Resource: "resource",
						splitPaths: []param{
							{
								name: "",
							},
							{
								name: "path1",
							},
						},
						queryValueMap: map[string]param{
							"param1": {
								name: "value1",
							},
						},
					},
				},
			}},
			domain:       "domain",
			method:       "get",
			path:         "/path1",
			query:        "param1=value1&param1=value2",
			wantAction:   "get",
			wantResource: "/path1",
		},
		{
			name: "query param didn't match",
			mappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Action:   "read",
						Resource: "resource",
						splitPaths: []param{
							{
								name: "",
							},
							{
								name: "path1",
							},
						},
						queryValueMap: map[string]param{
							"param2": {
								name: "value2",
							},
						},
					},
				},
			}},
			domain:       "domain",
			method:       "get",
			path:         "/path1",
			query:        "param1=value1",
			wantAction:   "get",
			wantResource: "/path1",
		},
		{
			name: "query value didn't match",
			mappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Action:   "read",
						Resource: "resource",
						splitPaths: []param{
							{
								name: "",
							},
							{
								name: "path1",
							},
						},
						queryValueMap: map[string]param{
							"param1": {
								name: "value2",
							},
						},
					},
				},
			}},
			domain:       "domain",
			method:       "get",
			path:         "/path1",
			query:        "param1=value1",
			wantAction:   "get",
			wantResource: "/path1",
		},
		{
			name: "request path is empty",
			mappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Action:   "read",
						Resource: "resource",
						splitPaths: []param{
							{
								name: "",
							},
							{
								name: "path1",
							},
						},
						queryValueMap: map[string]param{
							"param1": {
								name: "value1",
							},
						},
					},
				},
			}},
			domain:       "domain",
			method:       "get",
			path:         "",
			query:        "param1=value1",
			wantAction:   "get",
			wantResource: "",
		},
		{
			name: "if request path is empty, query matches",
			mappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Action:   "read",
						Resource: "resource.{placeholder}",
						splitPaths: []param{
							{
								name: "",
							},
						},
						queryValueMap: map[string]param{
							"param": {
								name:          "{placeholder}",
								isPlaceholder: true,
							},
						},
					},
				},
			}},
			domain:       "domain",
			method:       "get",
			path:         "",
			query:        "param=value",
			wantAction:   "read",
			wantResource: "resource.value",
		},
		{
			name: "request path is slash",
			mappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Action:   "read",
						Resource: "resource",
						splitPaths: []param{
							{
								name: "",
							},
							{
								name: "path1",
							},
						},
						queryValueMap: map[string]param{
							"param1": {
								name: "value1",
							},
						},
					},
				},
			}},
			domain:       "domain",
			method:       "get",
			path:         "/",
			query:        "param1=value1",
			wantAction:   "get",
			wantResource: "/",
		},
		{
			name: "if request path is slash, query matches",
			mappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Action:   "read",
						Resource: "resource.{placeholder}",
						splitPaths: []param{
							{
								name: "",
							},
							{
								name: "",
							},
						},
						queryValueMap: map[string]param{
							"param": {
								name:          "{placeholder}",
								isPlaceholder: true,
							},
						},
					},
				},
			}},
			domain:       "domain",
			method:       "get",
			path:         "/",
			query:        "param=value",
			wantAction:   "read",
			wantResource: "resource.value",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			action, resource, err := tt.mappingRules.Translate(tt.domain, tt.method, tt.path, tt.query)
			if err != nil {
				t.Errorf("an error occurred in Translate, err is %s", err.Error())
				return
			}

			if action != tt.wantAction || resource != tt.wantResource {
				t.Errorf("action(%s) is not the expected value %s, or resource(%s) is not the expected value %s",
					action, tt.wantAction, resource, tt.wantResource)
			}
		})
	}
}
