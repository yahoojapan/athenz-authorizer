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
		wantErr          string
	}{
		{
			name: "success",
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
						splitPaths: []SplitPath{
							{
								Path:        "path1",
								Placeholder: "",
							},
							{
								Path:        "path2",
								Placeholder: "",
							},
							{
								Path:        "path3",
								Placeholder: "",
							},
						},
						queryValueMap: map[string]QueryValue{},
					},
				},
			}},
		},
		{
			name: "success",
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
						splitPaths: []SplitPath{
							{
								Path:        "path1",
								Placeholder: "",
							},
							{
								Path:        "",
								Placeholder: "{placeholder1}",
							},
							{
								Path:        "path2",
								Placeholder: "",
							},
							{
								Path:        "",
								Placeholder: "{placeholder2}",
							},
						},
						queryValueMap: map[string]QueryValue{},
					},
				},
			}},
		},
		{
			name: "success",
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
						splitPaths: []SplitPath{
							{
								Path:        "path1",
								Placeholder: "",
							},
							{
								Path:        "path2",
								Placeholder: "",
							},
						},
						queryValueMap: map[string]QueryValue{
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
			name: "success",
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
						splitPaths: []SplitPath{
							{
								Path:        "path1",
								Placeholder: "",
							},
							{
								Path:        "",
								Placeholder: "{path2}",
							},
						},
						queryValueMap: map[string]QueryValue{
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
			name: "success",
			mappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Action:   "read",
						Resource: "resource",
						splitPaths: []SplitPath{
							{
								Path:        "path1",
								Placeholder: "",
							},
							{
								Path:        "path2",
								Placeholder: "",
							},
						},
						queryValueMap: map[string]QueryValue{},
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
			name: "success",
			mappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Action:   "read",
						Resource: "resource.{placeholder1}",
						splitPaths: []SplitPath{
							{
								Path:        "path1",
								Placeholder: "",
							},
							{
								Path:        "",
								Placeholder: "{placeholder1}",
							},
							{
								Path:        "path3",
								Placeholder: "",
							},
						},
						queryValueMap: map[string]QueryValue{},
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
			name: "success",
			mappingRules: MappingRules{Rules: map[string][]Rule{
				"domain": {
					Rule{
						Method:   "get",
						Action:   "read",
						Resource: "resource.{placeholder1}",
						splitPaths: []SplitPath{
							{
								Path:        "path1",
								Placeholder: "",
							},
							{
								Path:        "path2",
								Placeholder: "",
							},
						},
						queryValueMap: map[string]QueryValue{
							"param1": {
								Value:       "value1",
								Placeholder: "",
							},
							"param2": {
								Value:       "",
								Placeholder: "{placeholder1}",
							},
						},
					},
				},
			}},
			domain:       "domain",
			method:       "get",
			path:         "/path1/path2",
			query:        "param1=value1&param2=value2",
			wantAction:   "read",
			wantResource: "resource.value2",
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
