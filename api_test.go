package uma_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sort"
	"testing"

	"github.com/pckhoi/uma"
	"github.com/pckhoi/uma/pkg/rp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type Middleware func(next http.Handler) http.Handler

type handler struct {
	middlewares   []Middleware
	onUMAResource func(r *uma.Resource)
}

func (h *handler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	var o http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.onUMAResource != nil {
			h.onUMAResource(uma.GetResource(r))
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
	rscTemplates    uma.ResourceTemplates
	rscStore        uma.ResourceStore
	kp              *uma.KeycloakProvider
	h               *handler
	server          *httptest.Server
	lastResource    *uma.Resource
	userAccessToken map[string]string
}

func newMockAPI(t *testing.T, client *http.Client, types map[string]uma.ResourceType, rscTemplates uma.ResourceTemplates, basePath string, scopeMiddleware Middleware, includeScopeInPermission bool) *mockAPI {
	a := &mockAPI{
		types:           types,
		rscTemplates:    rscTemplates,
		rscStore:        make(mockResourceStore),
		kp:              createKeycloakProvider(t, client),
		h:               &handler{},
		userAccessToken: map[string]string{},
	}
	sort.Sort(sort.Reverse(rscTemplates))
	a.h.onUMAResource = func(r *uma.Resource) {
		a.lastResource = r
	}
	a.server = httptest.NewServer(a.h)
	a.baseURL = a.server.URL + basePath
	a.h.middlewares = []Middleware{
		uma.ResourceMiddleware(uma.ResourceMiddlewareOptions{
			GetBaseURL: func(r *http.Request) url.URL {
				u, _ := url.Parse(a.baseURL)
				return *u
			},
			GetProvider: func(r *http.Request) uma.Provider {
				return a.kp
			},
			ResourceStore:     a.rscStore,
			Types:             types,
			ResourceTemplates: a.rscTemplates,
			Client:            client,
		}),
	}
	if scopeMiddleware != nil {
		a.h.middlewares = append(a.h.middlewares,
			scopeMiddleware,
			uma.AuthorizeMiddleware(uma.AuthorizeMiddlewareOptions{
				IncludeScopeInPermissionTicket: includeScopeInPermission,
				GetProvider: func(r *http.Request) uma.Provider {
					return a.kp
				},
				DisableTokenExpirationCheck: true,
			}),
		)
	}
	return a
}

func (a *mockAPI) RegisterResource(t *testing.T, path string) {
	t.Helper()
	for _, tmpl := range a.rscTemplates {
		rsc := tmpl.Match(a.types, a.baseURL, path)
		if rsc != nil {
			resp, err := a.kp.CreateResource(rsc)
			require.NoError(t, err)
			a.rscStore.Set(rsc.Name, resp.ID)
			return
		}
	}
}

func (a *mockAPI) AssertResponseStatus(t *testing.T, method, path, accessToken string, statusCode int) {
	t.Helper()
	req, err := http.NewRequest(method, a.server.URL+path, nil)
	require.NoError(t, err)
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	assert.Equal(t, statusCode, resp.StatusCode, "response has status %d instead of %d", resp.StatusCode, statusCode)
}

var authHeaderRegex = regexp.MustCompile(`UMA\s+realm="([^"]+)",\s+as_uri="([^"]+)",\s+ticket="([^"]+)"`)

func extractTicketFrom401(t *testing.T, resp *http.Response) string {
	t.Helper()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	matches := authHeaderRegex.FindStringSubmatch(resp.Header.Get("WWW-Authenticate"))
	require.NotNil(t, matches)
	return matches[3]
}

func (a *mockAPI) requestRPT(t *testing.T, kc *rp.KeycloakClient, username, method, path, rptToUpdate string) (rpt string, err error) {
	t.Helper()
	req, err := http.NewRequest(method, a.server.URL+path, nil)
	require.NoError(t, err, "unable to create request")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err, "unable to token-free request")
	ticket := extractTicketFrom401(t, resp)
	accessToken, ok := a.userAccessToken[username]
	if !ok {
		accessToken, _, err = kc.AuthenticateUserWithPassword(username, "password")
		require.NoError(t, err, "unable to authenticate user")
		a.userAccessToken[username] = accessToken
		t.Logf("logged in user %q", username)
	} else {
		t.Logf("reuse access token for user %q", username)
	}
	return kc.RequestRPT(accessToken, rp.RPTRequest{
		Ticket: ticket,
		RPT:    rptToUpdate,
	})
}

func (a *mockAPI) AskForRPT(t *testing.T, kc *rp.KeycloakClient, username, method, path, rptToUpdate string) (rpt string) {
	t.Helper()
	var err error
	rpt, err = a.requestRPT(t, kc, username, method, path, rptToUpdate)
	require.NoError(t, err)
	return
}

func (a *mockAPI) AssertPermissionNotGranted(t *testing.T, kc *rp.KeycloakClient, username, method, path string) {
	t.Helper()
	_, err := a.requestRPT(t, kc, username, method, path, "")
	assert.Error(t, err)
}

func (a *mockAPI) Stop(t *testing.T) {
	a.server.Close()
}
