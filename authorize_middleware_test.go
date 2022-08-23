package uma_test

import (
	"net/http"
	"testing"

	"github.com/pckhoi/uma"
	"github.com/pckhoi/uma/pkg/rp"
	"github.com/stretchr/testify/require"
)

func createKeycloakRPClient(t *testing.T, client *http.Client) *rp.KeycloakClient {
	t.Helper()
	kc, err := rp.NewKeycloakClient(
		"http://localhost:8080/realms/test-realm",
		"test-client-2", "change-me",
		client,
	)
	require.NoError(t, err)
	return kc
}

func registerUserResources(t *testing.T, api *mockAPI) {
	t.Helper()
	api.RegisterResource(t, "/users")
	api.RegisterResource(t, "/users/1")
	for _, role := range []string{"reader", "writer"} {
		_, err := api.kp.CreatePermissionForResource(api.rscStore.Get("Users"), &uma.KcPermission{
			Name:        role + "-list-users",
			Description: role + " can list users",
			Scopes:      []string{"list"},
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

func TestAuthorizeMiddleware(t *testing.T) {
	client, stop := recordHTTP(t, "test_authorize_middleware", false)
	defer stop()
	api := mockUserAPI(t, client, true, true)
	defer api.Stop(t)
	registerUserResources(t, api)

	kc := createKeycloakRPClient(t, client)

	api.AssertResponseStatus(t, http.MethodGet, "/abc", "", http.StatusOK)

	rpt := api.AskForRPT(t, kc, "johnd", http.MethodGet, "/base/users", "")
	api.AssertResponseStatus(t, http.MethodGet, "/base/users", rpt, http.StatusOK)

	rpt = api.AskForRPT(t, kc, "johnd", http.MethodGet, "/base/users/1", rpt)
	api.AssertResponseStatus(t, http.MethodGet, "/base/users/1", rpt, http.StatusOK)
	api.AssertResponseStatus(t, http.MethodGet, "/base/users", rpt, http.StatusOK)
	api.AssertResponseStatus(t, http.MethodPost, "/base/users/1", rpt, http.StatusUnauthorized)

	rpt = api.AskForRPT(t, kc, "johnd", http.MethodPost, "/base/users/1", rpt)
	api.AssertResponseStatus(t, http.MethodPost, "/base/users/1", rpt, http.StatusOK)
	api.AssertResponseStatus(t, http.MethodGet, "/base/users/1", rpt, http.StatusOK)
	api.AssertResponseStatus(t, http.MethodGet, "/base/users", rpt, http.StatusOK)

	rpt = api.AskForRPT(t, kc, "alice", http.MethodGet, "/base/users/1", "")
	api.AssertResponseStatus(t, http.MethodGet, "/base/users/1", rpt, http.StatusOK)
	api.AssertResponseStatus(t, http.MethodGet, "/base/users", rpt, http.StatusUnauthorized)

	api.AssertPermissionNotGranted(t, kc, "alice", http.MethodPost, "/base/users/1")
}

func TestAuthorizeMiddlewareNoSpecificScope(t *testing.T) {
	client, stop := recordHTTP(t, "test_authorize_middleware_no_specific_scope", false)
	defer stop()
	api := mockUserAPI(t, client, true, false)
	defer api.Stop(t)
	registerUserResources(t, api)

	kc := createKeycloakRPClient(t, client)

	rpt := api.AskForRPT(t, kc, "johnd", http.MethodGet, "/base/users", "")
	api.AssertResponseStatus(t, http.MethodGet, "/base/users", rpt, http.StatusOK)

	rpt = api.AskForRPT(t, kc, "johnd", http.MethodGet, "/base/users/1", "")
	api.AssertResponseStatus(t, http.MethodGet, "/base/users/1", rpt, http.StatusOK)
	api.AssertResponseStatus(t, http.MethodPost, "/base/users/1", rpt, http.StatusOK)
	api.AssertResponseStatus(t, http.MethodGet, "/base/users", rpt, http.StatusUnauthorized)

	rpt = api.AskForRPT(t, kc, "alice", http.MethodGet, "/base/users/1", "")
	api.AssertResponseStatus(t, http.MethodGet, "/base/users/1", rpt, http.StatusOK)
	api.AssertResponseStatus(t, http.MethodPost, "/base/users/1", rpt, http.StatusUnauthorized)
	api.AssertResponseStatus(t, http.MethodGet, "/base/users", rpt, http.StatusUnauthorized)
}
