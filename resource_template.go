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
	_type     string
	nameTmpl  string
	pathTmpl  string
	pathRegex *regexp.Regexp
	depth     int
}

func NewResourceTemplate(pathTmpl, resourceType, nameTmpl string) *ResourceTemplate {
	depth := strings.Count(pathTmpl, "/")
	pattern := fmt.Sprintf("^(%s)(?:/.+)?$", paramRegex.ReplaceAllString(pathTmpl, `(?P<$1>[^/]+)`))
	pathRegex, err := regexp.Compile(pattern)
	if err != nil {
		panic(err)
	}
	return &ResourceTemplate{
		_type:     resourceType,
		nameTmpl:  nameTmpl,
		depth:     depth,
		pathRegex: pathRegex,
		pathTmpl:  pathTmpl,
	}
}

func (rt *ResourceTemplate) Match(types map[string]ResourceType, baseURL, path string) *Resource {
	matches := rt.pathRegex.FindStringSubmatch(path)
	if matches == nil {
		return nil
	}
	paramNames := rt.pathRegex.SubexpNames()
	name := rt.nameTmpl
	for _, paramName := range paramNames {
		if paramName == "" {
			continue
		}
		fmt.Printf("paramName: %q\n", paramName)
		name = strings.ReplaceAll(name, fmt.Sprintf("{%s}", paramName), matches[rt.pathRegex.SubexpIndex(paramName)])
	}
	return &Resource{
		ResourceType: types[rt._type],
		Name:         name,
		URI:          baseURL + matches[1],
	}
}

type ResourceTemplates []*ResourceTemplate

func (t ResourceTemplates) Len() int {
	return len(t)
}

func (t ResourceTemplates) Less(i, j int) bool {
	if t[i].depth < t[j].depth {
		return true
	} else if t[i].depth > t[j].depth {
		return false
	}
	return t[i].pathTmpl < t[j].pathTmpl
}

func (t ResourceTemplates) Swap(i, j int) {
	t[i], t[j] = t[j], t[i]
}
