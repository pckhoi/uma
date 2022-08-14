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

type OAuth2Flow struct {
	Scopes map[string]string `json:"scopes,omitempty" yaml:"scopes,omitempty"`
}

type SecurityScheme struct {
	UMAResourceTypes map[string]UMAResourceType `json:"x-uma-resource-types,omitempty" yaml:"x-uma-resource-types,omitempty"`
	Type             string                     `json:"type,omitempty" yaml:"type,omitempty"`
	// Flows            map[string]OAuth2Flow      `json:"flows,omitempty" yaml:"flows,omitempty"`
}

type Components struct {
	SecuritySchemes map[string]SecurityScheme `json:"securitySchemes,omitempty" yaml:"securitySchemes,omitempty"`
}

type Path struct {
	UMAResouce *UMAResouce `json:"x-uma-resource,omitempty" yaml:"x-uma-resource,omitempty"`
}

type Paths struct {
	UMAResouce *UMAResouce     `json:"x-uma-resource,omitempty" yaml:"x-uma-resource,omitempty"`
	Paths      map[string]Path `yaml:",inline"`
}

func (p *Paths) UnmarshalJSON(b []byte) error {
	m := map[string]json.RawMessage{}
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	p.Paths = map[string]Path{}
	for k, v := range m {
		if k == "x-uma-resource" {
			p.UMAResouce = &UMAResouce{}
			if err := json.Unmarshal(v, p.UMAResouce); err != nil {
				return err
			}
		} else {
			obj := &Path{}
			if err := json.Unmarshal(v, obj); err != nil {
				return err
			}
			p.Paths[k] = *obj
		}
	}
	return nil
}

type OpenAPISpec struct {
	Paths      *Paths      `json:"paths,omitempty" yaml:"paths,omitempty"`
	Components *Components `json:"components,omitempty" yaml:"components,omitempty"`
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
