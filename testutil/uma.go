package testutil

import (
	"io"
	"net/http"
	"regexp"
	"testing"

	"github.com/pckhoi/uma/pkg/rp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func DoRequest(t *testing.T, method, uri, accessToken string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, uri, nil)
	require.NoError(t, err)
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

func AssertResponse(t *testing.T, method, uri, accessToken string, statusCode int, contentType, content string) {
	t.Helper()
	resp := DoRequest(t, method, uri, accessToken)
	assert.Equal(t, statusCode, resp.StatusCode, "response has status %d instead of %d", resp.StatusCode, statusCode)
	assert.Equal(t, contentType, resp.Header.Get("Content-Type"), "response has content-type %s instead of %s", resp.Header.Get("Content-Type"), contentType)
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, content, string(b), "response has status %s instead of %s", string(b), content)
}

func AssertResponseStatus(t *testing.T, method, uri, accessToken string, statusCode int) {
	t.Helper()
	resp := DoRequest(t, method, uri, accessToken)
	assert.Equal(t, statusCode, resp.StatusCode, "response has status %d instead of %d", resp.StatusCode, statusCode)
}

var authHeaderRegex = regexp.MustCompile(`UMA\s+realm="([^"]+)",\s+as_uri="([^"]+)",\s+ticket="([^"]+)"`)

func extractTicketFrom401(t *testing.T, resp *http.Response) string {
	t.Helper()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	matches := authHeaderRegex.FindStringSubmatch(resp.Header.Get("WWW-Authenticate"))
	require.NotNil(t, matches)
	return matches[3]
}

func RequestRPT(t *testing.T, kc *rp.KeycloakClient, accessTokens map[string]string, username, method, uri, rptToUpdate string) (rpt string, err error) {
	t.Helper()
	req, err := http.NewRequest(method, uri, nil)
	require.NoError(t, err, "unable to create request")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err, "unable to token-free request")
	ticket := extractTicketFrom401(t, resp)
	accessToken, ok := accessTokens[username]
	if !ok {
		creds, err := kc.AuthenticateUserWithPassword(username, "password")
		require.NoError(t, err, "unable to authenticate user")
		accessToken = creds.AccessToken
		accessTokens[username] = accessToken
		t.Logf("logged in user %q", username)
	} else {
		t.Logf("reuse access token for user %q", username)
	}
	return kc.RequestRPT(accessToken, rp.RPTRequest{
		Ticket: ticket,
		RPT:    rptToUpdate,
	})
}

func AskForRPT(t *testing.T, kc *rp.KeycloakClient, accessTokens map[string]string, username, method, uri, rptToUpdate string) (rpt string) {
	t.Helper()
	var err error
	rpt, err = RequestRPT(t, kc, accessTokens, username, method, uri, rptToUpdate)
	require.NoError(t, err)
	return
}

func AssertPermissionNotGranted(t *testing.T, kc *rp.KeycloakClient, accessTokens map[string]string, username, method, uri string) {
	t.Helper()
	_, err := RequestRPT(t, kc, accessTokens, username, method, uri, "")
	assert.Error(t, err)
}
