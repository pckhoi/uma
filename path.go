package uma

import (
	"fmt"
	"regexp"
	"strings"
)

var paramRegex *regexp.Regexp

func init() {
	paramRegex = regexp.MustCompile(`\{([^}]+)\}`)
}

type ResourceTemplate struct {
	nameTmpl string
	_type    string
}

func NewResourceTemplate(rscType, rscNameTmpl string) *ResourceTemplate {
	return &ResourceTemplate{
		_type:    rscType,
		nameTmpl: rscNameTmpl,
	}
}

func (t *ResourceTemplate) CreateResource(types map[string]ResourceType, uri string, params map[string]string) (rsc *Resource) {
	uri = strings.TrimSuffix(uri, "/")
	var name string
	if t.nameTmpl != "" {
		name = t.nameTmpl
		for k, v := range params {
			name = strings.ReplaceAll(name, fmt.Sprintf("{%s}", k), v)
		}
	}
	rsc = &Resource{
		ResourceType: types[t._type],
		Name:         name,
		URI:          uri,
	}
	return
}

type Security []map[string][]string

func (s Security) findScopes(securitySchemes map[string]struct{}) (scopes []string) {
	if s == nil {
		return nil
	}
	for _, r := range s {
		for k, sl := range r {
			if _, ok := securitySchemes[k]; ok {
				return sl
			}
		}
	}
	return []string{}
}

type Operation struct {
	Security Security
}

type Path struct {
	len        int
	pathRegex  *regexp.Regexp
	rscTmpl    *ResourceTemplate
	operations map[string]Operation
}

func NewPath(pathTmpl string, rscTmpl *ResourceTemplate, operations map[string]Operation) Path {
	pattern := fmt.Sprintf("^(%s)/?$", paramRegex.ReplaceAllString(pathTmpl, `(?P<$1>[^/]+)`))
	pathRegex, err := regexp.Compile(pattern)
	if err != nil {
		panic(err)
	}
	return Path{
		len:        len(pathTmpl),
		pathRegex:  pathRegex,
		rscTmpl:    rscTmpl,
		operations: operations,
	}
}

func (p *Path) MatchPath(types map[string]ResourceType, baseURL, path string) (rsc *Resource, match bool) {
	matches := p.pathRegex.FindStringSubmatch(path)
	if matches == nil {
		return
	}
	match = true
	if p.rscTmpl != nil {
		paramNames := p.pathRegex.SubexpNames()
		params := map[string]string{}
		for _, paramName := range paramNames {
			if paramName == "" {
				continue
			}
			params[paramName] = matches[p.pathRegex.SubexpIndex(paramName)]
		}
		rsc = p.rscTmpl.CreateResource(types, baseURL+path, params)
	}
	return
}

func (p *Path) FindScopes(securitySchemes map[string]struct{}, method string) (scopes []string) {
	if op, ok := p.operations[method]; ok {
		return op.Security.findScopes(securitySchemes)
	}
	return nil
}
