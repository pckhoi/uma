package uma_test

import (
	"context"
	"embed"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/dnaeon/go-vcr/v2/recorder"
	"github.com/pckhoi/uma"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed fixtures/*.json
var fixtures embed.FS

func readFixture(t *testing.T, filename string, obj interface{}) {
	t.Helper()
	f, err := fixtures.Open("fixtures/" + filename)
	require.NoError(t, err)
	defer f.Close()
	b, err := io.ReadAll(f)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(b, obj))
}

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

func recordHTTP(t *testing.T, name string) (client *http.Client, stop func() error) {
	t.Helper()
	r, err := recorder.New("fixtures/go-vcr/" + name)
	require.NoError(t, err)
	client = &http.Client{}
	*client = *http.DefaultClient
	client.Transport = r
	return client, r.Stop
}

func TestResourceMiddleware(t *testing.T) {
	client, stop := recordHTTP(t, "test_resource_middleware")
	defer stop()
	var resource *uma.Resource
	h := &handler{
		onUMAResource: func(r *uma.Resource) {
			resource = r
		},
	}
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
	}

	_, err := http.Get(s.URL + "/abc")
	require.NoError(t, err)
	assert.Nil(t, resource)

	_, err = http.Get(s.URL + "/users")
	require.NoError(t, err)
	assert.Nil(t, resource)

	_, err = http.Get(s.URL + "/base/users")
	require.NoError(t, err)
	assert.NotEmpty(t, resource.ID)
	id1 := resource.ID
	assert.Equal(t, &uma.Resource{
		ResourceType: types["users"],
		Name:         "Users",
		URI:          s.URL + "/base/users",
		ID:           id1,
	}, resource)

	_, err = http.Get(s.URL + "/base/users/123")
	require.NoError(t, err)
	assert.NotEmpty(t, resource.ID)
	id2 := resource.ID
	assert.NotEqual(t, id2, id1)
	assert.Equal(t, &uma.Resource{
		ResourceType: types["user"],
		Name:         "User 123",
		URI:          s.URL + "/base/users/123",
		ID:           id2,
	}, resource)
}

func TestMarshalResource(t *testing.T) {
	resource := &uma.Resource{
		ResourceType: uma.ResourceType{
			Type:           "user",
			Description:    "A user",
			IconUri:        "https://example.com/rsrcs/user.png",
			ResourceScopes: []string{"read", "write"},
		},
		ID:   "123",
		Name: "User 123",
		URI:  "https://example.com/users/123",
	}
	b, err := json.MarshalIndent(resource, "		", "	")
	require.NoError(t, err)
	assert.Equal(t,
		`{
			"type": "user",
			"description": "A user",
			"icon_uri": "https://example.com/rsrcs/user.png",
			"resource_scopes": [
				"read",
				"write"
			],
			"_id": "123",
			"name": "User 123",
			"uri": "https://example.com/users/123"
		}`,
		string(b),
	)
}
