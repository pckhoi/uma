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
	m             Middleware
	onUMAResource func(r *uma.Resource)
}

func (h *handler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	h.m(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.onUMAResource(uma.GetResource(r))
	})).ServeHTTP(rw, req)
}

func TestResourceMiddleware(t *testing.T) {
	var resource *uma.Resource
	h := &handler{
		onUMAResource: func(r *uma.Resource) {
			resource = r
		},
	}
	s := httptest.NewServer(h)
	types := map[string]uma.ResourceType{
		"user": {
			Type:           "user",
			Description:    "A user",
			IconUri:        "https://example.com/rsrcs/user.png",
			ResourceScopes: []string{"read", "write"},
		},
		"users": {
			Type:           "users",
			Description:    "A list of users",
			IconUri:        "https://example.com/rsrcs/users.png",
			ResourceScopes: []string{"list"},
		},
	}
	h.m = uma.ResourceMiddleware(
		func(r *http.Request) url.URL {
			u, _ := url.Parse(s.URL + "/base")
			return *u
		},
		func(r *http.Request) uma.ProviderInfo {
			pi := &uma.ProviderInfo{}
			readFixture(t, "provider-info.json", pi)
			pi.KeySet = oidc.NewRemoteKeySet(context.Background(), pi.Issuer+"/protocol/openid-connect/certs")
			return *pi
		},
		types,
		uma.ResourceTemplates{
			uma.NewResourceTemplate("/users", "users", "Users"),
			uma.NewResourceTemplate("/users/{id}", "user", "User {id}"),
		},
	)

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
		Name:         s.URL + "/base/users",
		ID:           id1,
	}, resource)

	_, err = http.Get(s.URL + "/base/users/123")
	require.NoError(t, err)
	assert.NotEmpty(t, resource.ID)
	id2 := resource.ID
	assert.NotEqual(t, id2, id1)
	assert.Equal(t, &uma.Resource{
		ResourceType: types["user"],
		Name:         s.URL + "/base/users/123",
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
		Name: "https://example.com/users/123",
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
			"name": "https://example.com/users/123"
		}`,
		string(b),
	)
}
