package client

import (
	"context"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/pckhoi/uma/pkg/httputil"
	"github.com/pckhoi/uma/pkg/urlencode"
)

type KeycloakClient struct {
	oidc         *oidc.Provider
	clientID     string
	clientSecret string
	client       *http.Client
}

func NewKeycloakClient(issuer, clientID, clientSecret string, client *http.Client) (*KeycloakClient, error) {
	kc := &KeycloakClient{
		clientID:     clientID,
		clientSecret: clientSecret,
		client:       client,
	}
	if kc.client == nil {
		kc.client = http.DefaultClient
	}
	var err error
	kc.oidc, err = oidc.NewProvider(context.Background(), issuer)
	if err != nil {
		return nil, err
	}
	return kc, nil
}

type tokenResponse struct {
	IDToken     string `json:"id_token,omitempty"`
	AccessToken string `json:"access_token,omitempty"`
}

func (kc *KeycloakClient) AuthenticateUserWithPassword(username, password string) (accessToken, idToken string, err error) {
	params := map[string][]string{
		"grant_type": {"password"},
		"client_id":  {kc.clientID},
		"scope":      {"openid"},
		"username":   {username},
		"password":   {password},
	}
	if kc.clientSecret != "" {
		params["client_secret"] = []string{kc.clientSecret}
	}
	resp, err := httputil.PostFormUrlencoded(kc.client, kc.oidc.Endpoint().AuthURL, nil, params)
	if err != nil {
		return "", "", err
	}
	tok := &tokenResponse{}
	if err := httputil.DecodeJSONResponse(resp, tok); err != nil {
		return "", "", err
	}
	return tok.AccessToken, tok.IDToken, nil
}

type ClaimTokenFormat string

const (
	// AccessTokenFormat indicates that the ClaimToken parameter references an access token
	AccessTokenFormat ClaimTokenFormat = "urn:ietf:params:oauth:token-type:jwt"

	// IDTokenFormat indicates that the ClaimToken parameter references an OpenID Connect ID Token.
	IDTokenFormat ClaimTokenFormat = "https://openid.net/specs/openid-connect-core-1_0.html#IDToken"
)

type RPTRequest struct {
	// Ticket is optional. The most recent permission ticket received by the client as part of the UMA authorization process.
	Ticket string

	// ClaimToken  is optional. A string representing additional claims that should be considered by the server when evaluating
	// permissions for the resource(s) and scope(s) being requested. This parameter allows clients to push claims to Keycloak.
	// For more details about all supported token formats see ClaimTokenFormat parameter.
	ClaimToken string

	// ClaimTokenFormat is optional. A string indicating the format of the token specified in the ClaimToken parameter.
	// Inspect AccessTokenFormat and IDTokenFormat to learn more.
	ClaimTokenFormat ClaimTokenFormat

	// RPT is optional. A previously issued RPT which permissions should also be evaluated and added in a new one. This parameter
	// allows clients in possession of an RPT to perform incremental authorization where permissions are added on demand.
	RPT string `url:"rpt"`

	// Permission is optional. A string representing a set of one or more resources and scopes the client is seeking access.
	// This parameter can be defined multiple times in order to request permission for multiple resource and scopes.
	// This parameter is an extension to urn:ietf:params:oauth:grant-type:uma-ticket grant type in order to allow clients to
	// send authorization requests without a permission ticket. The format of the string must be: RESOURCE_ID#SCOPE_ID. For
	// instance: Resource A#Scope A, Resource A#Scope A, Scope B, Scope C, Resource A, #Scope A.
	Permission []string

	// Audience is optional. The client identifier of the resource server to which the client is seeking access. This parameter
	// is mandatory in case the permission parameter is defined. It serves as a hint to Keycloak to indicate the context in
	// which permissions should be evaluated.
	Audience string

	// ResponseIncludeResourceName is optional. A boolean value indicating to the server whether resource names should be included
	// in the RPT’s permissions. If false, only the resource identifier is included.
	ResponseIncludeResourceName bool

	// ResponsePermissionsLimit is optional. An integer N that defines a limit for the amount of permissions an RPT can have. When
	// used together with rpt parameter, only the last N requested permissions will be kept in the RPT.
	ResponsePermissionsLimit int

	// SubmitRequest is optional. A boolean value indicating whether the server should create permission requests to the resources
	// and scopes referenced by a permission ticket. This parameter only has effect if used together with the ticket parameter as
	// part of a UMA authorization process.
	SubmitRequest bool
}

func (kc *KeycloakClient) RequestRPT(accessToken string, request RPTRequest) (rpt string, err error) {
	values, err := urlencode.ToValues(request)
	if err != nil {
		return "", err
	}
	resp, err := httputil.PostFormUrlencoded(kc.client, kc.oidc.Endpoint().AuthURL, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+accessToken)
	}, *values)
	if err != nil {
		return "", err
	}
	tok := &tokenResponse{}
	if err := httputil.DecodeJSONResponse(resp, tok); err != nil {
		return "", err
	}
	return tok.AccessToken, nil
}
