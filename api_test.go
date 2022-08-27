package uma_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"testing"

	"github.com/pckhoi/uma"
	"github.com/stretchr/testify/require"
)

type Middleware func(next http.Handler) http.Handler

type handler struct {
	middlewares []Middleware
	onRequest   func(r *http.Request)
}

func (h *handler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	var o http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.onRequest != nil {
			h.onRequest(r)
		}
		w.WriteHeader(http.StatusOK)
	})
	for i := len(h.middlewares) - 1; i >= 0; i-- {
		o = h.middlewares[i](o)
	}
	o.ServeHTTP(rw, req)
}

type mockResourceStore map[string]string

func (s mockResourceStore) Set(name, id string) {
	s[name] = id
}

func (s mockResourceStore) Get(name string) string {
	id, ok := s[name]
	if !ok {
		return ""
	}
	return id
}

type mockAPI struct {
	types           map[string]uma.ResourceType
	baseURL         string
	rscStore        uma.ResourceStore
	kp              *uma.KeycloakProvider
	h               *handler
	server          *httptest.Server
	paths           []uma.Path
	lastResource    *uma.Resource
	lastScopes      []string
	lastClaims      *uma.Claims
	userAccessToken map[string]string
	securitySchemes map[string]struct{}
	defaultRscTmpl  *uma.ResourceTemplate
	man             *uma.Manager
}

func stringSet(sl []string) map[string]struct{} {
	m := map[string]struct{}{}
	for _, s := range sl {
		m[s] = struct{}{}
	}
	return m
}

func newMockAPI(
	t *testing.T,
	client *http.Client,
	basePath string,
	types map[string]uma.ResourceType,
	securitySchemes []string,
	defaultResource *uma.ResourceTemplate,
	defaultSecurity uma.Security,
	paths uma.Paths,
	includeScopeInPermission bool,
) *mockAPI {
	sort.Sort(paths)
	a := &mockAPI{
		types:           types,
		rscStore:        make(mockResourceStore),
		kp:              createKeycloakProvider(t, client),
		h:               &handler{},
		paths:           paths,
		userAccessToken: map[string]string{},
		securitySchemes: stringSet(securitySchemes),
		defaultRscTmpl:  defaultResource,
	}
	a.h.onRequest = func(r *http.Request) {
		a.lastResource = uma.GetResource(r)
		a.lastClaims = uma.GetClaims(r)
		a.lastScopes = uma.GetScopes(r)
	}
	a.server = httptest.NewServer(a.h)
	a.baseURL = a.server.URL + basePath
	a.man = uma.New(
		uma.ManagerOptions{
			GetBaseURL: func(r *http.Request) url.URL {
				u, _ := url.Parse(a.baseURL)
				return *u
			},
			GetProvider: func(r *http.Request) uma.Provider {
				return a.kp
			},
			ResourceStore:                   a.rscStore,
			IncludeScopesInPermissionTicket: includeScopeInPermission,
			DisableTokenExpirationCheck:     true,
		},
		types,
		securitySchemes,
		defaultResource,
		defaultSecurity,
		paths,
	)
	a.h.middlewares = []Middleware{a.man.Middleware}
	return a
}

func (a *mockAPI) RegisterResource(t *testing.T, path string) {
	t.Helper()
	var rsc *uma.Resource
	var ok bool
	for _, p := range a.paths {
		rsc, ok = p.MatchPath(a.types, a.baseURL, path)
		if ok {
			if rsc == nil && a.defaultRscTmpl != nil {
				rsc = a.defaultRscTmpl.CreateResource(a.types, a.baseURL+path, nil)
			}
			break
		}
	}
	if rsc != nil {
		resp, err := a.kp.CreateResource(rsc)
		require.NoError(t, err)
		a.rscStore.Set(rsc.Name, resp.ID)
		return
	}
}

func (a *mockAPI) Stop(t *testing.T) {
	a.server.Close()
}
