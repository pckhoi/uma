package uma_test

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/pckhoi/uma"
	"github.com/pckhoi/uma/pkg/rp"
	"github.com/pckhoi/uma/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createKeycloakProvider(t *testing.T, client *http.Client) *uma.KeycloakProvider {
	t.Helper()
	issuer := "http://localhost:8080/realms/test-realm"
	kp, err := uma.NewKeycloakProvider(
		issuer, "test-client", "change-me",
		oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), client), issuer+"/protocol/openid-connect/certs"),
		uma.WithKeycloakClient(client), uma.WithKeycloakOwnerManagedAccess(),
	)
	require.NoError(t, err)
	return kp
}

func assertIDsContains(t *testing.T, sl []string, id string) {
	t.Helper()
	sort.Strings(sl)
	i := sort.Search(len(sl), func(i int) bool { return sl[i] >= id })
	assert.True(t, i < len(sl) && sl[i] == id, "ids does not contain %q", id)
}

func assertIDsNotContains(t *testing.T, sl []string, id string) {
	t.Helper()
	sort.Strings(sl)
	i := sort.Search(len(sl), func(i int) bool { return sl[i] >= id })
	assert.True(t, i >= len(sl) || sl[i] != id, "ids contains %q", id)
}

func assertPermissionIDs(t *testing.T, perms []uma.KcPermission, ids ...string) {
	t.Helper()
	sort.Strings(ids)
	permIDs := make([]string, 0, len(perms))
	for _, p := range perms {
		permIDs = append(permIDs, p.ID)
	}
	sort.Strings(permIDs)
	assert.Equal(t, ids, permIDs)
}

func TestKeycloakProvider(t *testing.T) {
	client, stop := testutil.RecordHTTP(t, "test_keycloak_provider", false)
	defer stop()
	kp := createKeycloakProvider(t, client)
	kc := testutil.CreateKeycloakRPClient(t, client)
	baseURL := "https://example.com"

	rscReq1 := &uma.Resource{
		ResourceType: uma.ResourceType{
			Type:           baseURL + "/rsrcs/user",
			ResourceScopes: []string{"read", "write"},
		},
		Name: "User 1",
		URI:  baseURL + "/users/1",
	}
	rscResp1, err := kp.CreateResource(rscReq1)
	require.NoError(t, err)

	rsc, err := kp.GetResource(rscResp1.ID)
	require.NoError(t, err)
	assert.Equal(t, rscResp1.ID, rsc.ID)

	rscReq1.Name = "User Alice"
	require.NoError(t, kp.UpdateResource(rscResp1.ID, rscReq1))
	rsc, err = kp.GetResource(rscResp1.ID)
	require.NoError(t, err)
	assert.Equal(t, rscReq1.Name, rsc.Name)

	rscReq2 := &uma.Resource{
		ResourceType: uma.ResourceType{
			Type:           baseURL + "/rsrcs/user",
			ResourceScopes: []string{"read", "write"},
		},
		Name: "User 2",
		URI:  baseURL + "/users/2",
	}
	rscResp2, err := kp.CreateResource(rscReq2)
	require.NoError(t, err)

	ids, err := kp.ListResources(nil)
	require.NoError(t, err)
	assertIDsContains(t, ids, rscResp1.ID)
	assertIDsContains(t, ids, rscResp2.ID)

	ids, err = kp.ListResources(map[string][]string{
		"name": {"User 2"},
	})
	require.NoError(t, err)
	assertIDsNotContains(t, ids, rscResp1.ID)
	assertIDsContains(t, ids, rscResp2.ID)

	require.NoError(t, kp.DeleteResource(rscResp1.ID))
	_, err = kp.GetResource(rscResp1.ID)
	assert.Error(t, err)

	p1 := &uma.KcPermission{
		Name:        "reader-read-users",
		Description: "reader can read users",
		Scopes:      []string{"read"},
		Roles:       []string{"reader"},
	}
	pid1, err := kp.CreatePermissionForResource(rscResp2.ID, p1)
	require.NoError(t, err)

	ticket, err := kp.CreatePermissionTicket(rscResp2.ID, "read")
	require.NoError(t, err)
	token, _, err := kc.AuthenticateUserWithPassword("johnd", "password")
	require.NoError(t, err)
	rptStr, err := kc.RequestRPT(token, rp.RPTRequest{
		Ticket: ticket,
	})
	require.NoError(t, err)
	b, err := kp.VerifySignature(context.Background(), rptStr)
	require.NoError(t, err)
	rpt := &uma.Claims{}
	require.NoError(t, json.Unmarshal(b, rpt))
	assert.Equal(t, rscResp2.ID, rpt.Authorization.Permissions[0].Rsid)
	assert.Equal(t, "read", rpt.Authorization.Permissions[0].Scopes[0])

	p2 := &uma.KcPermission{
		Name:        "writer-write-users",
		Description: "writer can write users",
		Scopes:      []string{"write"},
		Roles:       []string{"writer"},
	}
	pid2, err := kp.CreatePermissionForResource(rscResp2.ID, p2)
	require.NoError(t, err)

	perms, err := kp.ListPermissions(nil)
	require.NoError(t, err)
	assertPermissionIDs(t, perms, pid1, pid2)
	perms, err = kp.ListPermissions(map[string][]string{
		"scope": {"write"},
	})
	require.NoError(t, err)
	assertPermissionIDs(t, perms, pid2)

	p1.Name = "Reader read"
	require.NoError(t, kp.UpdatePermission(pid1, p1))
	perms, err = kp.ListPermissions(map[string][]string{
		"name": {"Reader read"},
	})
	require.NoError(t, err)
	assertPermissionIDs(t, perms, pid1)

	require.NoError(t, kp.DeletePermission(pid1))
	perms, err = kp.ListPermissions(map[string][]string{
		"name": {"Reader read"},
	})
	require.NoError(t, err)
	assert.Len(t, perms, 0)
}
