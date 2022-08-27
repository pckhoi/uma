package uma

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

type ResourceStore interface {
	Set(name, id string)
	Get(name string) (id string)
}

type middleware struct {
	getBaseURL         func(r *http.Request) url.URL
	getProvider        func(r *http.Request) Provider
	resourceStore      ResourceStore
	includeScope       bool
	disableExpireCheck bool
	paths              []Path
	types              map[string]ResourceType
	securitySchemes    map[string]struct{}
	defaultRscTmpl     *ResourceTemplate
	defaultSecurity    Security
}

func (m *middleware) matchOperation(r *http.Request) (rsc *Resource, scopes []string) {
	baseURL := m.getBaseURL(r)
	if !strings.HasPrefix(r.URL.Path, baseURL.Path) {
		return
	}
	path := strings.TrimPrefix(r.URL.Path, baseURL.Path)
	if len(path) == 0 {
		path = "/"
	}
	var match bool
	for _, p := range m.paths {
		rsc, scopes, match = p.Match(m.types, m.securitySchemes, baseURL.String(), path, r.Method)
		if !match {
			continue
		}
		if rsc == nil && m.defaultRscTmpl != nil {
			rsc = m.defaultRscTmpl.CreateResource(m.types, baseURL.String()+path, nil)
		}
		if scopes == nil && m.defaultSecurity != nil {
			scopes = m.defaultSecurity.findScopes(m.securitySchemes)
		}
		return
	}
	return
}

func (m *middleware) registerResource(p Provider, rsc *Resource) {
	if s := m.resourceStore.Get(rsc.Name); s != "" {
		rsc.ID = s
		return
	}
	resp, err := p.CreateResource(rsc)
	if err != nil {
		panic(err)
	}
	m.resourceStore.Set(rsc.Name, resp.ID)
	rsc.ID = resp.ID
}

func getBearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if header != "" {
		if strings.HasPrefix(header, "Bearer ") {
			return strings.TrimPrefix(header, "Bearer ")
		}
	}
	return ""
}

func (m *middleware) askForTicket(w http.ResponseWriter, p Provider, resource *Resource, scopes ...string) {
	var ticket string
	var err error
	if m.includeScope {
		ticket, err = p.CreatePermissionTicket(resource.ID, scopes...)
	} else {
		ticket, err = p.CreatePermissionTicket(resource.ID)
	}
	if err != nil {
		panic(err)
	}
	directives := p.WWWAuthenticateDirectives()
	w.Header().Set("WWW-Authenticate",
		fmt.Sprintf(`UMA realm=%q, as_uri=%q, ticket=%q`, directives.Realm, directives.AsUri, ticket),
	)
	w.WriteHeader(http.StatusUnauthorized)
}

func (m *middleware) hasPermission(w http.ResponseWriter, r *http.Request, p Provider, rsc *Resource, scopes []string) (*Claims, bool) {
	token := getBearerToken(r)
	if token == "" {
		m.askForTicket(w, p, rsc, scopes...)
		return nil, false
	}
	b, err := p.VerifySignature(r.Context(), token)
	if err != nil {
		panic(err)
	}
	rpt := &Claims{}
	if err = json.Unmarshal(b, rpt); err != nil {
		panic(err)
	}
	if rpt.IsValid(rsc.ID, m.disableExpireCheck, scopes...) {
		return rpt, true
	}
	m.askForTicket(w, p, rsc, scopes...)
	return nil, false
}

func (m *middleware) enforce(w http.ResponseWriter, r *http.Request) (rsc *Resource, scopes []string, claims *Claims, ok bool) {
	rsc, scopes = m.matchOperation(r)
	if rsc == nil || len(scopes) == 0 {
		return nil, nil, nil, true
	}
	p := m.getProvider(r)
	m.registerResource(p, rsc)
	if claims, ok := m.hasPermission(w, r, p, rsc, scopes); ok {
		return rsc, scopes, claims, true
	}
	return nil, nil, nil, false
}

type MiddlewareOptions struct {
	// GetBaseURL returns the base url of the covered api. It is typically the "url" of the matching
	// server entry in openapi spec. It should have this format: "{SCHEME}://{PUBLIC_HOSTNAME}{ANY_BASE_PATH}"
	GetBaseURL func(r *http.Request) url.URL

	// GetProvider returns the provider info given the request. It allows you to use different UMA
	// providers for different requests if you so wish
	GetProvider func(r *http.Request) Provider

	// ResourceStore persistently stores resource name and id. Some UMA providers don't like to be told
	// twice about the same resource. This tells the middleware which resource is already registered so
	// it doesn't have to be registered again.
	ResourceStore ResourceStore

	IncludeScopeInPermissionTicket bool
	DisableTokenExpirationCheck    bool
}

func Middleware(
	opts MiddlewareOptions,
	types map[string]ResourceType,
	securitySchemes []string,
	defaultResource *ResourceTemplate,
	defaultSecurity Security,
	paths Paths,
) func(next http.Handler) http.Handler {
	sort.Sort(paths)
	m := &middleware{
		getBaseURL:         opts.GetBaseURL,
		getProvider:        opts.GetProvider,
		resourceStore:      opts.ResourceStore,
		includeScope:       opts.IncludeScopeInPermissionTicket,
		disableExpireCheck: opts.DisableTokenExpirationCheck,
		types:              types,
		paths:              paths,
		securitySchemes:    stringSet(securitySchemes),
		defaultRscTmpl:     defaultResource,
		defaultSecurity:    defaultSecurity,
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if rsc, scopes, claims, ok := m.enforce(w, r); ok {
				if rsc != nil {
					r = setResource(r, rsc)
				}
				if scopes != nil {
					r = setScopes(r, scopes)
				}
				if claims != nil {
					r = setClaims(r, claims)
				}
				next.ServeHTTP(w, r)
				return
			}
		})
	}
}
