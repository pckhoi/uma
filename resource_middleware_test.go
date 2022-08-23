package uma_test

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/dnaeon/go-vcr/v2/recorder"
	"github.com/pckhoi/uma"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func recordHTTP(t *testing.T, name string, update bool) (client *http.Client, stop func() error) {
	t.Helper()
	fixture := "fixtures/go-vcr/" + name
	if update {
		os.Remove(fixture + ".yaml")
	}
	r, err := recorder.New(fixture)
	require.NoError(t, err)
	client = &http.Client{}
	*client = *http.DefaultClient
	client.Transport = r
	return client, r.Stop
}

func createKeycloakProvider(t *testing.T, client *http.Client) *uma.KeycloakProvider {
	t.Helper()
	issuer := "http://localhost:8080/realms/test-realm"
	kp, err := uma.NewKeycloakProvider(
		issuer, "test-client", "change-me",
		oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), client), issuer+"/protocol/openid-connect/certs"),
		client, true,
	)
	require.NoError(t, err)
	return kp
}

func mockUserAPI(t *testing.T, client *http.Client, includeAuthorizeMiddleware, includeScopeInPermission bool) *mockAPI {
	var scopeMiddleware Middleware
	if includeAuthorizeMiddleware {
		scopeMiddleware = func(next http.Handler) http.Handler {
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
		}
	}
	return newMockAPI(t, client,
		map[string]uma.ResourceType{
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
		},
		uma.ResourceTemplates{
			uma.NewResourceTemplate("/users/{id}", "user", "User {id}"),
			uma.NewResourceTemplate("/users", "users", "Users"),
		},
		"/base",
		scopeMiddleware,
		includeScopeInPermission,
	)
}

func TestResourceMiddleware(t *testing.T) {
	client, stop := recordHTTP(t, "test_resource_middleware", false)
	defer stop()
	api := mockUserAPI(t, client, false, false)
	defer api.Stop(t)

	_, err := http.Get(api.server.URL + "/abc")
	require.NoError(t, err)
	assert.Nil(t, api.lastResource)

	_, err = http.Get(api.server.URL + "/users")
	require.NoError(t, err)
	assert.Nil(t, api.lastResource)

	_, err = http.Get(api.server.URL + "/base/users")
	require.NoError(t, err)
	assert.NotEmpty(t, api.lastResource.ID)
	id1 := api.lastResource.ID
	assert.Equal(t, &uma.Resource{
		ResourceType:       api.types["users"],
		Name:               "Users",
		URI:                api.server.URL + "/base/users",
		ID:                 id1,
		OwnerManagedAccess: true,
	}, api.lastResource)

	_, err = http.Get(api.server.URL + "/base/users/123")
	require.NoError(t, err)
	assert.NotEmpty(t, api.lastResource.ID)
	id2 := api.lastResource.ID
	assert.NotEqual(t, id2, id1)
	assert.Equal(t, &uma.Resource{
		ResourceType:       api.types["user"],
		Name:               "User 123",
		URI:                api.server.URL + "/base/users/123",
		ID:                 id2,
		OwnerManagedAccess: true,
	}, api.lastResource)
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
