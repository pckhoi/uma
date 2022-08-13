package runtime_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pckhoi/uma-codegen/runtime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type handler struct {
	m             runtime.Middleware
	onUMAResource func(r *runtime.UMAResource)
}

func (h *handler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	h.m(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.onUMAResource(runtime.GetUMAResource(r))
	})).ServeHTTP(rw, req)
}

func TestMiddleware(t *testing.T) {
	var resource *runtime.UMAResource
	h := &handler{
		onUMAResource: func(r *runtime.UMAResource) {
			resource = r
		},
	}
	s := httptest.NewServer(h)
	types := map[string]runtime.UMAResourceType{
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
	h.m = runtime.UMAResouceMiddleware(
		s.URL+"/base",
		types,
		map[string]string{
			"/users":      "users",
			"/users/{id}": "user",
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
	assert.Equal(t, &runtime.UMAResource{
		UMAResourceType: types["users"],
		Name:            s.URL + "/base/users",
	}, resource)

	_, err = http.Get(s.URL + "/base/users/123")
	require.NoError(t, err)
	assert.Equal(t, &runtime.UMAResource{
		UMAResourceType: types["user"],
		Name:            s.URL + "/base/users/123",
	}, resource)

	b, err := json.MarshalIndent(resource, "		", "	")
	require.NoError(t, err)
	assert.Equal(t,
		fmt.Sprintf(`{
			"type": "user",
			"description": "A user",
			"icon_uri": "https://example.com/rsrcs/user.png",
			"resource_scopes": [
				"read",
				"write"
			],
			"name": "%s/base/users/123"
		}`, s.URL),
		string(b),
	)
}
