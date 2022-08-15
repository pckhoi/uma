package uma

import (
	"context"
	"net/http"

	"github.com/pckhoi/uma/pkg/httputil"
)

// KeySet mirrors oidc.KeySet interface. Learn more at
// https://pkg.go.dev/github.com/coreos/go-oidc/v3/oidc#KeySet
type KeySet interface {
	// VerifySignature parses the JSON web token, verifies the signature, and returns
	// the raw payload. Header and claim fields are validated by other parts of the
	// package. For example, the KeySet does not need to check values such as signature
	// algorithm, issuer, and audience since the IDTokenVerifier validates these values
	// independently.
	//
	// If VerifySignature makes HTTP requests to verify the token, it's expected to
	// use any HTTP client associated with the context through ClientContext.
	VerifySignature(ctx context.Context, jwt string) (payload []byte, err error)
}

type Provider interface {
	KeySet

	DiscoverUMA() error
	DoRequest(req *http.Request) (*http.Response, error)
	RegisterResource(resource *Resource) (err error)
	RequestPermissionTicket(resourceID string, scopes ...string) (string, error)
	Realm() string
	AuthorizationServerURI() string
}

type ProviderType string

const (
	Keycloak ProviderType = "keycloak"
)

type ProviderInfo struct {
	Issuer       string       `json:"issuer,omitempty"`
	Type         ProviderType `json:"type,omitempty"`
	ClientID     string       `json:"clientId,omitempty"`
	ClientSecret string       `json:"clientSecret,omitempty"`
	KeySet       KeySet       `json:"-"`
}

type providerKey struct{}

func setProvider(r *http.Request, p Provider) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), providerKey{}, p))
}

func getProvider(r *http.Request) Provider {
	if v := r.Context().Value(providerKey{}); v != nil {
		return v.(Provider)
	}
	return nil
}

type ResourceStore interface {
	Set(name, id string)
	Get(name string) (id string)
}

type baseProvider struct {
	Issuer        string
	ClientID      string
	ClientSecret  string
	KeySet        KeySet
	UMADiscovery  UMADiscovery
	ClientCreds   *ClientCreds
	resourceStore ResourceStore
	client        *http.Client
}

func newBaseProvider(issuer, clientID, clientSecret string, keySet KeySet, resourceStore ResourceStore, client *http.Client) *baseProvider {
	return &baseProvider{
		Issuer:        issuer,
		ClientID:      clientID,
		ClientSecret:  clientSecret,
		KeySet:        keySet,
		resourceStore: resourceStore,
		client:        client,
	}
}

func (p *baseProvider) VerifySignature(ctx context.Context, jwt string) (payload []byte, err error) {
	return p.KeySet.VerifySignature(ctx, jwt)
}

func (p *baseProvider) registerResource(resource *Resource, register func() (resourceID string, err error)) (resourceID string, err error) {
	if s := p.resourceStore.Get(resource.Name); s != "" {
		return s, nil
	}
	resourceID, err = register()
	if err != nil {
		return "", err
	}
	p.resourceStore.Set(resource.Name, resourceID)
	return resourceID, nil
}

type createResourceResponse struct {
	ID string `json:"_id"`
}

func (p *baseProvider) RegisterResource(resource *Resource) (err error) {
	rid, err := p.registerResource(resource, func() (resourceID string, err error) {
		req, err := httputil.JSONRequest(http.MethodPost, p.UMADiscovery.ResourceRegistrationEndpoint, resource)
		if err != nil {
			return "", err
		}
		resp, err := p.DoRequest(req)
		if err != nil {
			return "", err
		}
		if err = httputil.Ensure2XX(resp); err != nil {
			return "", err
		}
		respObj := &createResourceResponse{}
		if err = httputil.DecodeJSONResponse(resp, respObj); err != nil {
			return "", err
		}
		return respObj.ID, nil
	})
	if err != nil {
		return
	}
	resource.ID = rid
	return nil
}

type permissionRequest struct {
	ResourceID     string   `json:"resource_id"`
	ResourceScopes []string `json:"resource_scopes"`
}

type permissionResponse struct {
	Ticket string `json:"ticket"`
}

func (p *baseProvider) RequestPermissionTicket(resourceID string, scopes ...string) (string, error) {
	req, err := httputil.JSONRequest(http.MethodPost, p.UMADiscovery.PermissionEndpoint, []permissionRequest{
		{ResourceID: resourceID, ResourceScopes: scopes},
	})
	if err != nil {
		return "", err
	}
	resp, err := p.DoRequest(req)
	if err != nil {
		return "", err
	}
	if err = httputil.Ensure2XX(resp); err != nil {
		return "", err
	}
	respObj := &permissionResponse{}
	if err = httputil.DecodeJSONResponse(resp, respObj); err != nil {
		return "", err
	}
	return respObj.Ticket, nil
}

func (p *baseProvider) Realm() string {
	panic("Realm unimplemented")
}

func (p *baseProvider) AuthorizationServerURI() string {
	return p.Issuer
}
