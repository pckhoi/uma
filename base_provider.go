package uma

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/pckhoi/uma/pkg/httputil"
)

type baseProvider struct {
	issuer       string
	clientID     string
	clientSecret string
	keySet       KeySet
	discovery    DiscoveryDoc
	client       *httputil.Client
}

func newBaseProvider(issuer, clientID, clientSecret string, keySet KeySet, client *httputil.Client) *baseProvider {
	p := &baseProvider{
		issuer:       issuer,
		clientID:     clientID,
		clientSecret: clientSecret,
		keySet:       keySet,
		client:       client,
	}
	return p
}

type DiscoveryDoc struct {
	TokenEndpoint                string `json:"token_endpoint,omitempty"`
	TokenIntrospectionEndpoint   string `json:"token_introspection_endpoint,omitempty"`
	ResourceRegistrationEndpoint string `json:"resource_registration_endpoint,omitempty"`
	PermissionEndpoint           string `json:"permission_endpoint,omitempty"`
	PolicyEndpoint               string `json:"policy_endpoint,omitempty"`
}

func (p *baseProvider) discover() error {
	resp, err := p.client.Get(p.issuer + "/.well-known/uma2-configuration")
	if err != nil {
		return err
	}
	doc := &DiscoveryDoc{}
	if err = httputil.DecodeJSONResponse(resp, doc); err != nil {
		return err
	}
	p.discovery = *doc
	return nil
}

func (p *baseProvider) VerifySignature(ctx context.Context, jwt string) (payload []byte, err error) {
	return p.keySet.VerifySignature(ctx, jwt)
}

func (p *baseProvider) Authenticate(client *http.Client) (*httputil.ClientCreds, error) {
	resp, err := p.client.PostFormUrlencoded(p.discovery.TokenEndpoint, nil, map[string][]string{
		"grant_type":    {"client_credentials"},
		"client_id":     {p.clientID},
		"client_secret": {p.clientSecret},
	})
	if err != nil {
		return nil, err
	}
	creds := &httputil.ClientCreds{}
	if err = httputil.DecodeJSONResponse(resp, creds); err != nil {
		return nil, err
	}
	return creds, nil
}

func (p *baseProvider) CreateResource(request *Resource) (response *ExpandedResource, err error) {
	response = &ExpandedResource{}
	if err = p.client.CreateObject(p.discovery.ResourceRegistrationEndpoint, request, response); err != nil {
		return nil, err
	}
	return response, nil
}

func (p *baseProvider) GetResource(id string) (resource *ExpandedResource, err error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/%s", p.discovery.ResourceRegistrationEndpoint, id), nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.client.DoRequest(req)
	if err != nil {
		return nil, err
	}
	if err = httputil.Ensure2XX(resp); err != nil {
		return nil, err
	}
	resource = &ExpandedResource{}
	if err = httputil.DecodeJSONResponse(resp, resource); err != nil {
		return nil, err
	}
	return resource, nil
}

func (p *baseProvider) UpdateResource(id string, resource *Resource) (err error) {
	return p.client.UpdateObject(fmt.Sprintf("%s/%s", p.discovery.ResourceRegistrationEndpoint, id), resource)
}

func (p *baseProvider) DeleteResource(id string) (err error) {
	return p.client.DeleteObject(fmt.Sprintf("%s/%s", p.discovery.ResourceRegistrationEndpoint, id))
}

func (p *baseProvider) ListResources(urlQuery url.Values) (ids []string, err error) {
	ids = []string{}
	if err = p.client.ListObjects(p.discovery.ResourceRegistrationEndpoint, urlQuery, &ids); err != nil {
		return
	}
	return ids, nil
}

type permissionRequest struct {
	ResourceID     string   `json:"resource_id,omitempty"`
	ResourceScopes []string `json:"resource_scopes,omitempty"`
}

type permissionResponse struct {
	Ticket string `json:"ticket"`
}

func (p *baseProvider) CreatePermissionTicket(resourceID string, scopes ...string) (string, error) {
	respObj := &permissionResponse{}
	if err := p.client.CreateObject(p.discovery.PermissionEndpoint, []permissionRequest{
		{ResourceID: resourceID, ResourceScopes: scopes},
	}, respObj); err != nil {
		return "", err
	}
	return respObj.Ticket, nil
}
