package uma

import (
	"net/http"
)

// ProviderInfoGetter returns provider info based on request
type ProviderInfoGetter func(r *http.Request) ProviderInfo

type middleware struct {
	rm              *resourceMatcher
	getProviderInfo ProviderInfoGetter
	providers       map[string]Provider
}

func (m *middleware) getProvider(r *http.Request) (*http.Request, Provider) {
	pinfo := m.getProviderInfo(r)
	if v, ok := m.providers[pinfo.Issuer]; ok {
		return setProvider(r, v), v
	}
	var p Provider
	switch pinfo.Type {
	case Keycloak:
		p = &keycloakProvider{
			baseProvider: newBaseProvider(pinfo.Issuer, pinfo.ClientID, pinfo.ClientSecret, pinfo.KeySet),
		}

	}
	m.providers[pinfo.Issuer] = p
	if err := p.DiscoverUMA(); err != nil {
		panic(err)
	}
	return setProvider(r, p), p
}

// ResourceMiddleware detects UMAResource by matching request path with paths. types is the map between
// resource type and UMAResourceType. paths is the map between path template and resouce type as defined
// in OpenAPI spec.
func ResourceMiddleware(getBaseURL BaseURLGetter, getProviderInfo ProviderInfoGetter, types map[string]ResourceType, resourceTemplates ResourceTemplates) func(next http.Handler) http.Handler {
	rm := newResourceMatcher(getBaseURL, types, resourceTemplates)
	m := &middleware{
		rm:              rm,
		getProviderInfo: getProviderInfo,
		providers:       map[string]Provider{},
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var resource *Resource
			r, resource = m.rm.match(r)
			if resource != nil {
				var p Provider
				r, p = m.getProvider(r)
				if err := p.RegisterResource(resource); err != nil {
					panic(err)
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
