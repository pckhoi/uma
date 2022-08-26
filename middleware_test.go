package uma_test

import (
	"net/http"
	"testing"

	"github.com/pckhoi/uma"
	"github.com/pckhoi/uma/testutil"
	"github.com/stretchr/testify/require"
)

func mockUserAPI(t *testing.T, client *http.Client, includeScopeInPermission bool) *mockAPI {
	return newMockAPI(t, client, "/users",
		map[string]uma.ResourceType{
			"user": {
				Type:           "user",
				IconUri:        "https://example.com/rsrcs/user.png",
				ResourceScopes: []string{"read", "write"},
			},
			"users": {
				Type:           "users",
				IconUri:        "https://example.com/rsrcs/users.png",
				ResourceScopes: []string{"read"},
			},
		},
		[]string{"oidc"},
		uma.NewResourceTemplate("users", "Users"),
		[]map[string][]string{
			{"oidc": {"read"}},
		},
		uma.Paths{
			uma.NewPath("/", nil, map[string]uma.Operation{
				http.MethodGet: {},
			}),
			uma.NewPath("/{id}", uma.NewResourceTemplate("user", "User {id}"), map[string]uma.Operation{
				http.MethodGet: {},
				http.MethodPost: {
					Security: []map[string][]string{
						{"oidc": {"write"}},
					},
				},
			}),
		},
		includeScopeInPermission,
	)
}

func registerUserResources(t *testing.T, api *mockAPI) {
	t.Helper()
	api.RegisterResource(t, "/")
	api.RegisterResource(t, "/1")
	for _, role := range []string{"reader", "writer"} {
		_, err := api.kp.CreatePermissionForResource(api.rscStore.Get("Users"), &uma.KcPermission{
			Name:        role + "-read-users",
			Description: role + " can read users",
			Scopes:      []string{"read"},
			Roles:       []string{role},
		})
		require.NoError(t, err)
		_, err = api.kp.CreatePermissionForResource(api.rscStore.Get("User 1"), &uma.KcPermission{
			Name:        role + "-read-user",
			Description: role + " can read user",
			Scopes:      []string{"read"},
			Roles:       []string{role},
		})
		require.NoError(t, err)
	}
	_, err := api.kp.CreatePermissionForResource(api.rscStore.Get("User 1"), &uma.KcPermission{
		Name:        "writer-write-user",
		Description: "Writers can write user",
		Scopes:      []string{"write"},
		Roles:       []string{"writer"},
	})
	require.NoError(t, err)
}

func TestMiddleware(t *testing.T) {
	client, stop := testutil.RecordHTTP(t, "test_middleware", false)
	defer stop()
	api := mockUserAPI(t, client, true)
	defer api.Stop(t)
	registerUserResources(t, api)

	kc := testutil.CreateKeycloakRPClient(t, client)

	testutil.AssertResponseStatus(t, http.MethodGet, api.server.URL+"/abc", "", http.StatusOK)

	rpt := testutil.AskForRPT(t, kc, api.userAccessToken, "johnd", http.MethodGet, api.server.URL+"/users", "")
	testutil.AssertResponseStatus(t, http.MethodGet, api.server.URL+"/users", rpt, http.StatusOK)

	rpt = testutil.AskForRPT(t, kc, api.userAccessToken, "johnd", http.MethodGet, api.server.URL+"/users/1", rpt)
	testutil.AssertResponseStatus(t, http.MethodGet, api.server.URL+"/users/1", rpt, http.StatusOK)
	testutil.AssertResponseStatus(t, http.MethodGet, api.server.URL+"/users", rpt, http.StatusOK)
	testutil.AssertResponseStatus(t, http.MethodPost, api.server.URL+"/users/1", rpt, http.StatusUnauthorized)

	rpt = testutil.AskForRPT(t, kc, api.userAccessToken, "johnd", http.MethodPost, api.server.URL+"/users/1", rpt)
	testutil.AssertResponseStatus(t, http.MethodPost, api.server.URL+"/users/1", rpt, http.StatusOK)
	testutil.AssertResponseStatus(t, http.MethodGet, api.server.URL+"/users/1", rpt, http.StatusOK)
	testutil.AssertResponseStatus(t, http.MethodGet, api.server.URL+"/users", rpt, http.StatusOK)

	rpt = testutil.AskForRPT(t, kc, api.userAccessToken, "alice", http.MethodGet, api.server.URL+"/users/1", "")
	testutil.AssertResponseStatus(t, http.MethodGet, api.server.URL+"/users/1", rpt, http.StatusOK)
	testutil.AssertResponseStatus(t, http.MethodGet, api.server.URL+"/users", rpt, http.StatusUnauthorized)

	testutil.AssertPermissionNotGranted(t, kc, api.userAccessToken, "alice", http.MethodPost, api.server.URL+"/users/1")
}

func TestMiddlewareNoSpecificScope(t *testing.T) {
	client, stop := testutil.RecordHTTP(t, "test_middleware_no_specific_scope", false)
	defer stop()
	api := mockUserAPI(t, client, false)
	defer api.Stop(t)
	registerUserResources(t, api)

	kc := testutil.CreateKeycloakRPClient(t, client)

	rpt := testutil.AskForRPT(t, kc, api.userAccessToken, "johnd", http.MethodGet, api.server.URL+"/users", "")
	testutil.AssertResponseStatus(t, http.MethodGet, api.server.URL+"/users", rpt, http.StatusOK)

	rpt = testutil.AskForRPT(t, kc, api.userAccessToken, "johnd", http.MethodGet, api.server.URL+"/users/1", "")
	testutil.AssertResponseStatus(t, http.MethodGet, api.server.URL+"/users/1", rpt, http.StatusOK)
	testutil.AssertResponseStatus(t, http.MethodPost, api.server.URL+"/users/1", rpt, http.StatusOK)
	testutil.AssertResponseStatus(t, http.MethodGet, api.server.URL+"/users", rpt, http.StatusUnauthorized)

	rpt = testutil.AskForRPT(t, kc, api.userAccessToken, "alice", http.MethodGet, api.server.URL+"/users/1", "")
	testutil.AssertResponseStatus(t, http.MethodGet, api.server.URL+"/users/1", rpt, http.StatusOK)
	testutil.AssertResponseStatus(t, http.MethodPost, api.server.URL+"/users/1", rpt, http.StatusUnauthorized)
	testutil.AssertResponseStatus(t, http.MethodGet, api.server.URL+"/users", rpt, http.StatusUnauthorized)
}
