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
	"reflect"
	"testing"
)

func TestMappingRules_Validate(t *testing.T) {
	tests := []struct {
		name             string
		mappingRules     map[string][]Rule
		wantMappingRules MappingRules
		wantErrStr       string
	}{
		{
			name: "success only path",
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
						splitPaths: []Validated{
							{
								Value:       "path1",
								Placeholder: "",
							},
							{
								Value:       "path2",
								Placeholder: "",
							},
							{
								Value:       "path3",
								Placeholder: "",
							},
						},
						queryValueMap: map[string]Validated{},
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
						splitPaths: []Validated{
							{
								Value:       "path1",
								Placeholder: "",
							},
							{
								Value:       "",
								Placeholder: "",
							},
							{
								Value:       "path2",
								Placeholder: "",
							},
						},
						queryValueMap: map[string]Validated{},
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
						splitPaths: []Validated{
							{
								Value:       "path1",
								Placeholder: "",
							},
							{
								Value:       "",
								Placeholder: "{placeholder1}",
							},
							{
								Value:       "path2",
								Placeholder: "",
							},
							{
								Value:       "",
								Placeholder: "{placeholder2}",
							},
						},
						queryValueMap: map[string]Validated{},
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
						splitPaths: []Validated{
							{
								Value:       "path1",
								Placeholder: "",
							},
							{
								Value:       "path2",
								Placeholder: "",
							},
						},
						queryValueMap: map[string]Validated{
							"param1": {
								Value:       "value1",
								Placeholder: "",
							},
							"param2": {
								Value:       "value2",
								Placeholder: "",
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
						splitPaths: []Validated{
							{
								Value:       "path1",
								Placeholder: "",
							},
						},
						queryValueMap: map[string]Validated{
							"param1": {
								Value:       "value1?",
								Placeholder: "",
							},
							"param2": {
								Value:       "value2",
								Placeholder: "",
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
						splitPaths: []Validated{
							{
								Value:       "path1",
								Placeholder: "",
							},
							{
								Value:       "",
								Placeholder: "{path2}",
							},
						},
						queryValueMap: map[string]Validated{
							"param1": {
								Value:       "value1",
								Placeholder: "",
							},
							"param2": {
								Value:       "",
								Placeholder: "{value2}",
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
		},
		{
			name: "error query value is array",
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
			wantErrStr: "",
		},
		{
			name: "error rules is empty",
			mappingRules: map[string][]Rule{
				"domain": nil,
			},
			wantErrStr: "",
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
			wantErrStr: "",
		},
		{
			name: "error path is empty",
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
			wantErrStr: "",
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
			wantErrStr: "",
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
			wantErrStr: "",
		},
		{
			name: "error path is slash only",
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
			wantErrStr: "",
		},
		{
			name: "error path is no slash",
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
			wantErrStr: "",
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
			wantErrStr: "",
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
			wantErrStr: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mr := MappingRules{tt.mappingRules}
			err := mr.Validate()
			if err != nil {
				t.Errorf("err is %s", err.Error())
				return
			}
			for domain, rules := range mr.Rules {
				for i, rule := range rules {
					wantRules, ok := tt.wantMappingRules.Rules[domain]
					if !ok {
						t.Errorf("err is")
						return
					}
					if !reflect.DeepEqual(rule.splitPaths, wantRules[i].splitPaths) ||
						!reflect.DeepEqual(rule.queryValueMap, wantRules[i].queryValueMap) {
						t.Errorf("err is")
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
		wantErr      string
	}{
		{
			name: "success path only",
			mappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Action:   "read",
						Resource: "resource",
						splitPaths: []Validated{
							{
								Value:       "path1",
								Placeholder: "",
							},
							{
								Value:       "path2",
								Placeholder: "",
							},
						},
						queryValueMap: map[string]Validated{},
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
			name: "success path with placeholder",
			mappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Action:   "read",
						Resource: "resource.{placeholder1}",
						splitPaths: []Validated{
							{
								Value:       "path1",
								Placeholder: "",
							},
							{
								Value:       "",
								Placeholder: "{placeholder1}",
							},
							{
								Value:       "path3",
								Placeholder: "",
							},
						},
						queryValueMap: map[string]Validated{},
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
			name: "success path with placeholder",
			mappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Action:   "read",
						Resource: "resource.{placeholder1}.{placeholder1}.{placeholder1}",
						splitPaths: []Validated{
							{
								Value:       "path1",
								Placeholder: "",
							},
							{
								Value:       "",
								Placeholder: "{placeholder1}",
							},
							{
								Value:       "path3",
								Placeholder: "",
							},
						},
						queryValueMap: map[string]Validated{},
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
			name: "success path and query with placeholder",
			mappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Action:   "read",
						Resource: "resource.{placeholder1}.{placeholder2}",
						splitPaths: []Validated{
							{
								Value:       "path1",
								Placeholder: "",
							},
							{
								Value:       "",
								Placeholder: "{placeholder1}",
							},
						},
						queryValueMap: map[string]Validated{
							"param1": {
								Value:       "value1",
								Placeholder: "",
							},
							"param2": {
								Value:       "",
								Placeholder: "{placeholder2}",
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
			name: "success the length of path is not equal",
			mappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Action:   "read",
						Resource: "resource",
						splitPaths: []Validated{
							{
								Value:       "path1",
								Placeholder: "",
							},
							{
								Value:       "",
								Placeholder: "{placeholder1}",
							},
						},
						queryValueMap: map[string]Validated{},
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
			name: "success path does not match",
			mappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Action:   "read",
						Resource: "resource",
						splitPaths: []Validated{
							{
								Value:       "",
								Placeholder: "{placeholder1}",
							},
							{
								Value:       "path3",
								Placeholder: "",
							},
						},
						queryValueMap: map[string]Validated{},
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
			name: "success the length of query is not equal",
			mappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Action:   "read",
						Resource: "resource",
						splitPaths: []Validated{
							{
								Value:       "path1",
								Placeholder: "",
							},
						},
						queryValueMap: map[string]Validated{
							"param1": {
								Value:       "value1",
								Placeholder: "",
							},
							"param2": {
								Value:       "",
								Placeholder: "{placeholder2}",
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
			name: "success path does not match",
			mappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Action:   "read",
						Resource: "resource",
						splitPaths: []Validated{
							{
								Value:       "",
								Placeholder: "{placeholder1}",
							},
							{
								Value:       "path3",
								Placeholder: "",
							},
						},
						queryValueMap: map[string]Validated{},
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
			name: "success query values is array",
			mappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Action:   "read",
						Resource: "resource",
						splitPaths: []Validated{
							{
								Value:       "path1",
								Placeholder: "",
							},
						},
						queryValueMap: map[string]Validated{
							"param1": {
								Value:       "value1",
								Placeholder: "",
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
			name: "success query does not match",
			mappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Action:   "read",
						Resource: "resource",
						splitPaths: []Validated{
							{
								Value:       "path1",
								Placeholder: "",
							},
						},
						queryValueMap: map[string]Validated{
							"param2": {
								Value:       "value2",
								Placeholder: "",
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
			name: "success query does not match",
			mappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Action:   "read",
						Resource: "resource",
						splitPaths: []Validated{
							{
								Value:       "path1",
								Placeholder: "",
							},
						},
						queryValueMap: map[string]Validated{
							"param1": {
								Value:       "value2",
								Placeholder: "",
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
			name:         "success mappingRules is nil",
			mappingRules: MappingRules{Rules: nil},
			domain:       "domain",
			method:       "get",
			path:         "/path1",
			query:        "param1=value1",
			wantAction:   "get",
			wantResource: "/path1",
		},
		{
			name: "success request path is empty",
			mappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Action:   "read",
						Resource: "resource",
						splitPaths: []Validated{
							{
								Value:       "path1",
								Placeholder: "",
							},
						},
						queryValueMap: map[string]Validated{
							"param1": {
								Value:       "value2",
								Placeholder: "",
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
			name: "success request path is slash",
			mappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Action:   "read",
						Resource: "resource",
						splitPaths: []Validated{
							{
								Value:       "path1",
								Placeholder: "",
							},
						},
						queryValueMap: map[string]Validated{
							"param1": {
								Value:       "value2",
								Placeholder: "",
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			action, resource, err := tt.mappingRules.Translate(tt.domain, tt.method, tt.path, tt.query)
			if err != nil {
				if err.Error() != tt.wantErr {
					t.Errorf("err")
					return
				}
			} else {
				if tt.wantErr != "" {
					t.Errorf("err")
					return
				}
			}
			if action != tt.wantAction || resource != tt.wantResource {
				t.Errorf("action(%s) is not the expected value %s, or resource(%s) is not the expected value %s",
					action, tt.wantAction, resource, tt.wantResource)
			}
		})
	}
}
