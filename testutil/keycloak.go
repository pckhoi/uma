package testutil

import (
	"net/http"
	"testing"

	"github.com/pckhoi/uma/pkg/rp"
	"github.com/stretchr/testify/require"
)

func CreateKeycloakRPClient(t *testing.T, client *http.Client) *rp.KeycloakClient {
	t.Helper()
	kc, err := rp.NewKeycloakClient(
		"http://localhost:8080/realms/test-realm",
		"test-client-2", "change-me",
		client,
	)
	require.NoError(t, err)
	return kc
}
