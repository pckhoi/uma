package types

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type UMAResouce struct {
	Type         string `json:"type,omitempty" yaml:"type,omitempty"`
	NameTemplate string `json:"name,omitempty" yaml:"name,omitempty"`
}

type UMAResourceType struct {
	Description    string   `json:"description,omitempty" yaml:"description,omitempty"`
	IconUri        string   `json:"iconUri,omitempty" yaml:"iconUri,omitempty"`
	ResourceScopes []string `json:"resourceScopes,omitempty" yaml:"resourceScopes,omitempty"`
}

type SecurityScheme struct {
	Type       string `json:"type,omitempty" yaml:"type,omitempty"`
	UMAEnabled bool   `json:"x-uma-enabled,omitempty" yaml:"x-uma-enabled,omitempty"`
}

type Components struct {
	SecuritySchemes map[string]SecurityScheme `json:"securitySchemes,omitempty" yaml:"securitySchemes,omitempty"`
}

type Operation struct {
	Security []map[string][]string `json:"security,omitempty" yaml:"security,omitempty"`
}

type Path struct {
	UMAResouce *UMAResouce `json:"x-uma-resource,omitempty" yaml:"x-uma-resource,omitempty"`
	Get        *Operation  `json:"get,omitempty" yaml:"get,omitempty"`
	Post       *Operation  `json:"post,omitempty" yaml:"post,omitempty"`
	Put        *Operation  `json:"put,omitempty" yaml:"put,omitempty"`
	Patch      *Operation  `json:"patch,omitempty" yaml:"patch,omitempty"`
	Delete     *Operation  `json:"delete,omitempty" yaml:"delete,omitempty"`
	Head       *Operation  `json:"head,omitempty" yaml:"head,omitempty"`
	Options    *Operation  `json:"options,omitempty" yaml:"options,omitempty"`
	Trace      *Operation  `json:"trace,omitempty" yaml:"trace,omitempty"`
}

type OpenAPISpec struct {
	UMAResourceTypes map[string]UMAResourceType `json:"x-uma-resource-types,omitempty" yaml:"x-uma-resource-types,omitempty"`
	UMAResouce       *UMAResouce                `json:"x-uma-resource,omitempty" yaml:"x-uma-resource,omitempty"`
	Paths            map[string]Path            `json:"paths,omitempty" yaml:"paths,omitempty"`
	Components       *Components                `json:"components,omitempty" yaml:"components,omitempty"`
}

func OpenOpenAPISpec(filepath string) (*OpenAPISpec, error) {
	b, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	doc := &OpenAPISpec{}
	if strings.HasSuffix(filepath, ".yaml") || strings.HasSuffix(filepath, ".yml") {
		if err := yaml.Unmarshal(b, doc); err != nil {
			return nil, err
		}
	} else if strings.HasSuffix(filepath, ".json") {
		if err := json.Unmarshal(b, doc); err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("unanticipated file extension: %s", filepath)
	}
	return doc, nil
}
