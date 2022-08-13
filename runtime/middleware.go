package runtime

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

var paramRegex *regexp.Regexp

func init() {
	paramRegex = regexp.MustCompile(`\{[^}]+\}`)
}

// UMAResourceType describes and provides defaults for an UMA resource. Learn more at
// https://docs.kantarainitiative.org/uma/wg/oauth-uma-federated-authz-2.0-09.html#resource-set-desc
type UMAResourceType struct {
	Type           string   `json:"type,omitempty"`
	Description    string   `json:"description,omitempty"`
	IconUri        string   `json:"icon_uri,omitempty"`
	ResourceScopes []string `json:"resource_scopes,omitempty"`
}

// UMAResource describes an UMA resource. This object when rendered as JSON, can be
// used directly as request payload to create the resource.
type UMAResource struct {
	UMAResourceType

	// Name is the URI where the resource was detected
	Name string `json:"name,omitempty"`
}

type umaResourceKey struct{}

func setUMAResource(r *http.Request, ur *UMAResource) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), umaResourceKey{}, ur))
}

// GetUMAResource returns an UMAResource if one was discovered by UMAResouceMiddleware
func GetUMAResource(r *http.Request) *UMAResource {
	if v := r.Context().Value(umaResourceKey{}); v != nil {
		return v.(*UMAResource)
	}
	return nil
}

type sortableResourceType struct {
	path  string
	regex *regexp.Regexp
	depth int
	desc  UMAResourceType
}

func processResourceType(path string, rt UMAResourceType) (*sortableResourceType, error) {
	depth := strings.Count(path, "/")
	pattern := fmt.Sprintf("^(%s)(?:/.+)?$", paramRegex.ReplaceAllString(path, `[^/]+`))
	fmt.Printf("pattern %s\n", pattern)
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return &sortableResourceType{
		path:  path,
		regex: regex,
		depth: depth,
		desc:  rt,
	}, nil
}

type sortedResourceTypes []*sortableResourceType

func (t sortedResourceTypes) Len() int {
	return len(t)
}

func (t sortedResourceTypes) Less(i, j int) bool {
	if t[i].depth < t[j].depth {
		return true
	} else if t[i].depth > t[j].depth {
		return false
	}
	return t[i].path < t[j].path
}

func (t sortedResourceTypes) Swap(i, j int) {
	t[i], t[j] = t[j], t[i]
}

func sortResourceTypes(types map[string]UMAResourceType, paths map[string]string) (sortedResourceTypes, error) {
	sl := make(sortedResourceTypes, 0, len(paths))
	for k, v := range paths {
		rt, err := processResourceType(k, types[v])
		if err != nil {
			return nil, err
		}
		sl = append(sl, rt)
	}
	sort.Sort(sort.Reverse(sl))
	return sl, nil
}

type resourceMatcher struct {
	baseURL *url.URL
	types   sortedResourceTypes
}

func newResourceMatcher(baseURLStr string, types map[string]UMAResourceType, paths map[string]string) (*resourceMatcher, error) {
	baseURL, err := url.Parse(baseURLStr)
	if err != nil {
		return nil, err
	}
	m := &resourceMatcher{
		baseURL: baseURL,
	}
	m.types, err = sortResourceTypes(types, paths)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func (m *resourceMatcher) matchResourceType(req *http.Request) (uri string, t *UMAResourceType) {
	if !strings.HasPrefix(req.URL.Path, m.baseURL.Path) {
		return "", nil
	}
	path := strings.TrimPrefix(req.URL.Path, m.baseURL.Path)
	for _, rt := range m.types {
		match := rt.regex.FindStringSubmatch(path)
		if match != nil {
			t = &UMAResourceType{}
			*t = rt.desc
			uri = m.baseURL.String() + match[1]
			return
		}
	}
	return "", nil
}

func (m *resourceMatcher) match(req *http.Request) *http.Request {
	uri, t := m.matchResourceType(req)
	if uri != "" {
		return setUMAResource(req, &UMAResource{
			Name:            uri,
			UMAResourceType: *t,
		})
	}
	return req
}

// Middleware is just a plain http middleware
type Middleware func(next http.Handler) http.Handler

// UMAResouceMiddleware detects UMAResource by matching request path with paths. types is the map between
// resource type and UMAResourceType. paths is the map between path template and resouce type as defined
// in OpenAPI spec.
func UMAResouceMiddleware(baseURL string, types map[string]UMAResourceType, paths map[string]string) Middleware {
	m, err := newResourceMatcher(baseURL, types, paths)
	if err != nil {
		panic(err)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r = m.match(r)
			next.ServeHTTP(w, r)
		})
	}
}
