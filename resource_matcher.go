package uma

import (
	"context"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// ResourceType describes and provides defaults for an UMA resource. Learn more at
// https://docs.kantarainitiative.org/uma/wg/oauth-uma-federated-authz-2.0-09.html#resource-set-desc
type ResourceType struct {
	Type           string   `json:"type,omitempty"`
	Description    string   `json:"description,omitempty"`
	IconUri        string   `json:"icon_uri,omitempty"`
	ResourceScopes []string `json:"resource_scopes,omitempty"`
}

// Resource describes an UMA resource. This object when rendered as JSON, can be
// used directly as request payload to create the resource.
type Resource struct {
	ResourceType

	// ID is the identifier defined by the authorization server
	ID string `json:"_id,omitempty"`

	// Name is the URI where the resource was detected
	Name string `json:"name,omitempty"`

	// Keycloak only fields
	Owner              string `json:"owner,omitempty"`
	OwnerManagedAccess bool   `json:"ownerManagedAccess,omitempty"`
	URI                string `json:"uri,omitempty"`
}

type resourceKey struct{}

func setResource(r *http.Request, ur *Resource) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), resourceKey{}, ur))
}

// GetResource returns an UMAResource if one was discovered by UMAResouceMiddleware
func GetResource(r *http.Request) *Resource {
	if v := r.Context().Value(resourceKey{}); v != nil {
		return v.(*Resource)
	}
	return nil
}

// BaseURLGetter returns a string of this format:
// "{SCHEME}://{PUBLIC_HOSTNAME}{ANY_BASE_PATH}"
type BaseURLGetter func(r *http.Request) url.URL

type resourceMatcher struct {
	resourceTemplates ResourceTemplates
	getBaseURL        BaseURLGetter
	types             map[string]ResourceType
}

func newResourceMatcher(getBaseURL BaseURLGetter, types map[string]ResourceType, resourceTemplates ResourceTemplates) *resourceMatcher {
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
