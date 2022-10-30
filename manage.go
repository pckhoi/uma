package uma

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-logr/logr"
)

// ResourceStore persists resource name and id as registered with the provider
type ResourceStore interface {
	// Set resource id associated with given name
	Set(name, id string) error

	// Get resource id associated with given name. If this function returns
	// empty string, the Manager creates a new resource, registers it with the
	// provider, and persists the id using Set
	Get(name string) (id string, err error)
}

type Manager struct {
	getBaseURL               func(r *http.Request) url.URL
	getProvider              func(r *http.Request) Provider
	getResourceStore         func(r *http.Request) ResourceStore
	includeScopes            bool
	disableExpireCheck       bool
	paths                    []Path
	types                    map[string]ResourceType
	securitySchemes          map[string]struct{}
	defaultRscTmpl           *ResourceTemplate
	defaultSecurity          Security
	getResourceName          func(r *http.Request, rsc Resource) string
	customEnforce            func(r *http.Request, resource Resource, scopes []string) bool
	editUnauthorizedResponse func(rw http.ResponseWriter)
	anonymousScopes          func(r *http.Request, resource Resource) (scopes []string)
	logger                   *logr.Logger
}

type ManagerOptions struct {
	// GetBaseURL returns the base url of the covered api. It is typically the "url" of the matching
	// server entry in openapi spec. It should have this format: "{SCHEME}://{PUBLIC_HOSTNAME}{ANY_BASE_PATH}"
	GetBaseURL func(r *http.Request) url.URL

	// GetProvider returns the provider info given the request. It allows you to use different UMA
	// providers for different requests if you so wish
	GetProvider func(r *http.Request) Provider

	// ResourceStore persistently stores resource name and id. This tells the middleware which resource
	// is already registered so it doesn't have to be registered again.
	GetResourceStore func(r *http.Request) ResourceStore

	// Includes scopes in permission ticket in order to be granted specific scopes (the currently needed scopes)
	// on a resource. If scopes are not included, the authorization server might decides to grant all scopes
	// on the request resource.
	IncludeScopesInPermissionTicket bool

	// Skip token expiration check during token validation. This is only useful during testing, don't set
	// to true in production.
	DisableTokenExpirationCheck bool

	// GetResourceName if defined, must return the correct name of the resource. The preferred way to set resource
	// name is to define name template for the resource (x-uma-resource.name) in the OpenAPI spec. This method
	// should only be used when that is not possible.
	GetResourceName func(r *http.Request, rsc Resource) string

	// CustomEnforce handler if defined, cut the UMA provider out of the flow entirely, and allows deciding access
	// with custom logic. If the handler return true, allow the request to come through. Otherwise, responds with 401.
	CustomEnforce func(r *http.Request, resource Resource, scopes []string) bool

	// EditUnauthorizedResponse allows you to add additional headers and write custom body for 401 unauthorized
	// responses. Whatever you do, don't touch the "WWW-Authenticate" header as that is how the ticket is
	// transferred. Also make sure to write headers with status code 401.
	EditUnauthorizedResponse func(rw http.ResponseWriter)

	// AnonymousScopes is invoked when the user is unauthenticated. It is given the resource object that is being
	// accessed and should return the scopes available to anonymous users. If the scopes are sufficient, the user
	// is allowed to access. Otherwise an UMA ticket is created and returned in 401 response as usual.
	AnonymousScopes func(r *http.Request, resource Resource) (scopes []string)

	// If provided, Logger prints auth interactions
	Logger *logr.Logger
}

func New(
	opts ManagerOptions,
	types map[string]ResourceType,
	securitySchemes []string,
	defaultResource *ResourceTemplate,
	defaultSecurity Security,
	paths []Path,
) *Manager {
	return &Manager{
		getBaseURL:               opts.GetBaseURL,
		getProvider:              opts.GetProvider,
		getResourceStore:         opts.GetResourceStore,
		includeScopes:            opts.IncludeScopesInPermissionTicket,
		disableExpireCheck:       opts.DisableTokenExpirationCheck,
		types:                    types,
		paths:                    paths,
		securitySchemes:          stringSet(securitySchemes),
		defaultRscTmpl:           defaultResource,
		defaultSecurity:          defaultSecurity,
		getResourceName:          opts.GetResourceName,
		customEnforce:            opts.CustomEnforce,
		editUnauthorizedResponse: opts.EditUnauthorizedResponse,
		anonymousScopes:          opts.AnonymousScopes,
		logger:                   opts.Logger,
	}
}

func (m *Manager) info(msg string, args ...any) {
	if m.logger != nil {
		m.logger.Info(msg, args...)
	}
}

func (m *Manager) matchPath(r *http.Request, baseURL url.URL, path string) (*Resource, *Path) {
	if !strings.HasPrefix(path, baseURL.Path) {
		return nil, nil
	}
	path = strings.TrimPrefix(path, baseURL.Path)
	if len(path) == 0 {
		path = "/"
	}
	for _, p := range m.paths {
		rsc, ok := p.MatchPath(m.types, baseURL.String(), path)
		if !ok {
			continue
		}
		if rsc == nil && m.defaultRscTmpl != nil {
			rsc = m.defaultRscTmpl.CreateResource(m.types, baseURL.String()+path, nil)
		}
		if m.getResourceName != nil {
			rsc.Name = m.getResourceName(r, *rsc)
		}
		return rsc, &p
	}
	return nil, nil
}

func (m *Manager) matchOperation(r *http.Request) (rsc *Resource, scopes []string) {
	baseURL := m.getBaseURL(r)
	baseURL.Path = strings.TrimSuffix(baseURL.Path, "/")
	rsc, p := m.matchPath(r, baseURL, r.URL.Path)
	if rsc == nil {
		return
	}
	scopes = p.FindScopes(m.securitySchemes, r.Method)
	if scopes == nil && m.defaultSecurity != nil {
		scopes = m.defaultSecurity.findScopes(m.securitySchemes)
	}
	return
}

func (m *Manager) registerResource(rs ResourceStore, p Provider, rsc *Resource) error {
	if s, err := rs.Get(rsc.Name); err == nil && s != "" {
		rsc.ID = s
		m.info("fetched resource from store",
			"id", rsc.ID,
			"name", rsc.Name,
			"uri", rsc.URI,
		)
		return nil
	}
	resp, err := p.CreateResource(rsc)
	if err != nil {
		return err
	}
	if err := rs.Set(rsc.Name, resp.ID); err != nil {
		return err
	}
	rsc.ID = resp.ID
	m.info("created resource",
		"id", rsc.ID,
		"name", rsc.Name,
		"uri", rsc.URI,
	)
	return nil
}

// RegisterResourceAt finds resource at path. If one is found, it registers the resource with the provider.
// If a resource is not found, both rsc and err are nil.
func (m *Manager) RegisterResourceAt(r *http.Request, rs ResourceStore, p Provider, baseURL url.URL, path string) (rsc *Resource, err error) {
	rsc, _ = m.matchPath(r, baseURL, path)
	if rsc == nil {
		return
	}
	if err := m.registerResource(rs, p, rsc); err != nil {
		return nil, err
	}
	return rsc, nil
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

func (m *Manager) writeUnauthorizedResponse(w http.ResponseWriter) {
	if m.editUnauthorizedResponse != nil {
		m.editUnauthorizedResponse(w)
	} else {
		w.WriteHeader(http.StatusUnauthorized)
	}
}

func (m *Manager) AskForTicket(w http.ResponseWriter, r *http.Request) {
	p := m.getProvider(r)
	rsc := GetResource(r)
	scopes := GetScopes(r)
	m.askForTicket(w, p, rsc, scopes...)
}

func (m *Manager) askForTicket(w http.ResponseWriter, p Provider, resource *Resource, scopes ...string) {
	var ticket string
	var err error
	if m.includeScopes {
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
	m.writeUnauthorizedResponse(w)
}

func (m *Manager) loggerWithValues(args ...any) *logr.Logger {
	if m.logger != nil {
		l := m.logger.WithValues(args...)
		return &l
	}
	return nil
}

func (m *Manager) hasPermission(w http.ResponseWriter, r *http.Request, p Provider, rsc *Resource, scopes []string) (*Claims, bool) {
	token := getBearerToken(r)
	if token == "" {
		if m.anonymousScopes != nil && scopesAreSufficient(
			m.loggerWithValues(
				"method", r.Method,
				"path", r.URL.Path,
				"anonymous", true,
			),
			m.anonymousScopes(r, *rsc),
			scopes,
		) {
			return nil, true
		}
		m.askForTicket(w, p, rsc, scopes...)
		return nil, false
	}
	b, err := p.VerifySignature(r.Context(), token)
	if err != nil {
		m.info("invalid token signature",
			"method", r.Method,
			"path", r.URL.Path,
		)
		m.askForTicket(w, p, rsc, scopes...)
		return nil, false
	}
	rpt := &Claims{}
	if err = json.Unmarshal(b, rpt); err != nil {
		panic(err)
	}
	if rpt.IsValid(
		m.loggerWithValues(
			"method", r.Method,
			"path", r.URL.Path,
		),
		rsc.ID,
		m.disableExpireCheck,
		scopes...,
	) {
		return rpt, true
	}
	m.askForTicket(w, p, rsc, scopes...)
	return nil, false
}

func (m *Manager) enforce(w http.ResponseWriter, r *http.Request) (rsc *Resource, scopes []string, claims *Claims, ok bool) {
	rsc, scopes = m.matchOperation(r)
	if rsc == nil || len(scopes) == 0 {
		m.info("operation skipped because either resource or scopes are empty",
			"method", r.Method,
			"path", r.URL.Path,
		)
		return nil, nil, nil, true
	}
	if m.customEnforce != nil {
		m.info("use custom enforce handler",
			"method", r.Method,
			"path", r.URL.Path,
		)
		ok = m.customEnforce(r, *rsc, scopes)
		if !ok {
			m.writeUnauthorizedResponse(w)
		}
		return
	}
	p := m.getProvider(r)
	rs := m.getResourceStore(r)
	if err := m.registerResource(rs, p, rsc); err != nil {
		panic(err)
	}
	if claims, ok := m.hasPermission(w, r, p, rsc, scopes); ok {
		return rsc, scopes, claims, true
	}
	return nil, nil, nil, false
}

// Middleware is a http middleware that does the following things:
//   - Find the resource and required scopes based on request URL and method
//   - Register the resource with the provider if it's not already registered
//   - If a token isn't included or if the token does not have permission, get
//     an UMA ticket from the provider, returns the UMA ticket in
//     WWW-Authenticate header.
//   - If a token is included and valid, set resource, scopes, and claims in
//     the request context. They can be retrieved with GetResource, GetScopes,
//     and GetClaims respectively.
func (m *Manager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rsc, scopes, claims, ok := m.enforce(w, r); ok {
			args := []any{
				"method", r.Method,
				"path", r.URL.Path,
			}
			if rsc != nil {
				args = append(args, "resource_id", rsc.ID)
				r = setResource(r, rsc)
			}
			if scopes != nil {
				args = append(args, "scopes", scopes)
				r = setScopes(r, scopes)
			}
			if claims != nil {
				args = append(args, "claims", claims)
				r = setClaims(r, claims)
			}
			m.info("access granted", args...)
			next.ServeHTTP(w, r)
			return
		} else {
			m.info("access denied",
				"method", r.Method,
				"path", r.URL.Path,
			)
		}
	})
}
