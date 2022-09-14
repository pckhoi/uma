package uma_test

import (
	"net/http"
	"testing"

	"github.com/pckhoi/uma"
	"github.com/pckhoi/uma/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mockUserAPI(t *testing.T, client *http.Client, opts uma.ManagerOptions) *mockAPI {
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
		[]uma.Path{
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
		opts,
	)
}

func registerUserResources(t *testing.T, api *mockAPI) {
	t.Helper()
	idUsers := api.RegisterResource(t, "/")
	idUser1 := api.RegisterResource(t, "/1")
	for _, role := range []string{"reader", "writer"} {
		_, err := api.kp.CreatePermissionForResource(idUsers, &uma.KcPermission{
			Name:        role + "-read-users",
			Description: role + " can read users",
			Scopes:      []string{"read"},
			Roles:       []string{role},
		})
		require.NoError(t, err)
		_, err = api.kp.CreatePermissionForResource(idUser1, &uma.KcPermission{
			Name:        role + "-read-user",
			Description: role + " can read user",
			Scopes:      []string{"read"},
			Roles:       []string{role},
		})
		require.NoError(t, err)
	}
	_, err := api.kp.CreatePermissionForResource(idUser1, &uma.KcPermission{
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
	api := mockUserAPI(t, client, uma.ManagerOptions{IncludeScopesInPermissionTicket: true})
	defer api.Stop(t)
	registerUserResources(t, api)

	kc := testutil.CreateKeycloakRPClient(t, client)

	testutil.AssertResponseStatus(t, http.MethodGet, api.server.URL+"/abc", "", http.StatusOK)

	rpt := testutil.AskForRPT(t, kc, api.userAccessToken, "johnd", http.MethodGet, api.server.URL+"/users", "")
	testutil.AssertResponseStatus(t, http.MethodGet, api.server.URL+"/users", rpt, http.StatusOK)
	assert.Equal(t, &uma.Resource{
		ResourceType: uma.ResourceType{
			Type:           "users",
			IconUri:        "https://example.com/rsrcs/users.png",
			ResourceScopes: []string{"read"},
		},
		ID:   "f2bbda3a-76ad-411a-92bc-1bc21a2a60a0",
		Name: "Users",
		URI:  api.server.URL + "/users",
	}, api.lastResource)
	assert.Equal(t, []string{"read"}, api.lastScopes)
	assert.Equal(t, &uma.Claims{
		Authorization: &uma.Authorization{
			Permissions: []uma.Permission{
				{
					Rsid:   "f2bbda3a-76ad-411a-92bc-1bc21a2a60a0",
					Rsname: "Users",
					Scopes: []string{"read"},
				},
			},
		},
		Email:             "john.doe@example.com",
		Name:              "John Doe",
		GivenName:         "John",
		FamilyName:        "Doe",
		PreferredUsername: "johnd",
		Aud:               "test-client",
		Sid:               "4605692f-c7f2-4b0f-b285-7976dbe6997c",
		Jti:               "0e4dd304-7dee-40ef-baad-31fb90aa46e0",
		Exp:               1661483516,
		Iat:               1661483216,
		Sub:               "3461cf5b-12e5-49a9-8ca8-656375411ca3",
		Typ:               "Bearer",
		Azp:               "test-client-2",
	}, api.lastClaims)

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
	api := mockUserAPI(t, client, uma.ManagerOptions{
		EditUnauthorizedResponse: func(rw http.ResponseWriter) {
			rw.Header().Add("Content-Type", "application/json")
			rw.WriteHeader(http.StatusUnauthorized)
			rw.Write([]byte(`{"message":"Unauthorized"}`))
		},
	})
	defer api.Stop(t)
	registerUserResources(t, api)

	kc := testutil.CreateKeycloakRPClient(t, client)

	rpt := testutil.AskForRPT(t, kc, api.userAccessToken, "johnd", http.MethodGet, api.server.URL+"/users", "")
	testutil.AssertResponseStatus(t, http.MethodGet, api.server.URL+"/users", rpt, http.StatusOK)

	rpt = testutil.AskForRPT(t, kc, api.userAccessToken, "johnd", http.MethodGet, api.server.URL+"/users/1", "")
	testutil.AssertResponseStatus(t, http.MethodGet, api.server.URL+"/users/1", rpt, http.StatusOK)
	testutil.AssertResponseStatus(t, http.MethodPost, api.server.URL+"/users/1", rpt, http.StatusOK)
	testutil.AssertResponse(t, http.MethodGet, api.server.URL+"/users", rpt, http.StatusUnauthorized, "application/json", `{"message":"Unauthorized"}`)

	rpt = testutil.AskForRPT(t, kc, api.userAccessToken, "alice", http.MethodGet, api.server.URL+"/users/1", "")
	testutil.AssertResponseStatus(t, http.MethodGet, api.server.URL+"/users/1", rpt, http.StatusOK)
	testutil.AssertResponse(t, http.MethodPost, api.server.URL+"/users/1", rpt, http.StatusUnauthorized, "application/json", `{"message":"Unauthorized"}`)
	testutil.AssertResponse(t, http.MethodGet, api.server.URL+"/users", rpt, http.StatusUnauthorized, "application/json", `{"message":"Unauthorized"}`)
}

func TestMiddlewareAnonymousAccess(t *testing.T) {
	client, stop := testutil.RecordHTTP(t, "test_middleware_anonymous_access", false)
	defer stop()
	api := mockUserAPI(t, client, uma.ManagerOptions{
		AnonymousScopes: func(r *http.Request, resource uma.Resource) (scopes []string) {
			return []string{"read"}
		},
	})
	defer api.Stop(t)
	testutil.AssertResponseStatus(t, http.MethodGet, api.server.URL+"/users/1", "", http.StatusOK)
	testutil.AssertResponseStatus(t, http.MethodPost, api.server.URL+"/users/1", "", http.StatusUnauthorized)
}
