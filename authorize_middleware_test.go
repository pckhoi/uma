package uma_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/pckhoi/uma"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthorizeMiddleware(t *testing.T) {
	client, stop := recordHTTP(t, "test_resource_middleware")
	defer stop()
	h := &handler{}
	s := httptest.NewServer(h)
	defer s.Close()
	types := map[string]uma.ResourceType{
		"user": {
			Type:           "user",
			IconUri:        "https://example.com/rsrcs/user.png",
			ResourceScopes: []string{"read", "write"},
		},
		"users": {
			Type:           "users",
			IconUri:        "https://example.com/rsrcs/users.png",
			ResourceScopes: []string{"list"},
		},
	}
	h.middlewares = []Middleware{
		uma.ResourceMiddleware(uma.ResourceMiddlewareOptions{
			GetBaseURL: func(r *http.Request) url.URL {
				u, _ := url.Parse(s.URL + "/base")
				return *u
			},
			GetProviderInfo: func(r *http.Request) uma.ProviderInfo {
				pi := &uma.ProviderInfo{}
				readFixture(t, "provider-info.json", pi)
				pi.KeySet = oidc.NewRemoteKeySet(context.Background(), pi.Issuer+"/protocol/openid-connect/certs")
				return *pi
			},
			ResourceStore: make(mockResourceStore),
			Types:         types,
			ResourceTemplates: uma.ResourceTemplates{
				uma.NewResourceTemplate("/users", "users", "Users"),
				uma.NewResourceTemplate("/users/{id}", "user", "User {id}"),
			},
			Client: client,
		}),
		func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				resource := uma.GetResource(r)
				if resource != nil {
					if r.Method == http.MethodGet {
						if resource.Type == "users" {
							r = uma.SetScope(r, "list")
						} else {
							r = uma.SetScope(r, "read")
						}
					} else {
						r = uma.SetScope(r, "write")
					}
				}
				next.ServeHTTP(w, r)
			})
		},
		uma.AuthorizeMiddleware(true),
	}

	resp, err := http.Get(s.URL + "/abc")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	resp, err = http.Get(s.URL + "/base/users")
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}
