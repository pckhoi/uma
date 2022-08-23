package uma

import (
	"net/http"
	"net/url"
	"sort"
	"strings"
)

type URLGetter func(r *http.Request) url.URL

type resourceMatcher struct {
	resourceTemplates ResourceTemplates
	getBaseURL        URLGetter
	types             map[string]ResourceType
}

func newResourceMatcher(getBaseURL URLGetter, types map[string]ResourceType, resourceTemplates ResourceTemplates) *resourceMatcher {
	sort.Sort(sort.Reverse(resourceTemplates))
	return &resourceMatcher{
		getBaseURL:        getBaseURL,
		resourceTemplates: resourceTemplates,
		types:             types,
	}
}

func (m *resourceMatcher) match(req *http.Request) (*http.Request, *Resource) {
	baseURL := m.getBaseURL(req)
	if !strings.HasPrefix(req.URL.Path, baseURL.Path) {
		return req, nil
	}
	path := strings.TrimPrefix(req.URL.Path, baseURL.Path)
	for _, rt := range m.resourceTemplates {
		rsc := rt.Match(m.types, baseURL.String(), path)
		if rsc != nil {
			return setResource(req, rsc), rsc
		}
	}
	return req, nil
}
