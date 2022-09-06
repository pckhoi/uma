package uma

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/pckhoi/uma/pkg/httputil"
)

type KeycloakProvider struct {
	*baseProvider
	ownerManagedAccess bool
	_client            *http.Client
}

type KeycloakOption func(kp *KeycloakProvider)

// WithKeycloakClient directs KeycloakProvider to use a custom http client
func WithKeycloakClient(client *http.Client) KeycloakOption {
	return func(kp *KeycloakProvider) {
		kp._client = client
	}
}

// WithKeycloakOwnerManagedAccess sets ownerManagedAccess for each resource to true
// during resource creation
func WithKeycloakOwnerManagedAccess() KeycloakOption {
	return func(kp *KeycloakProvider) {
		kp.ownerManagedAccess = true
	}
}

func NewKeycloakProvider(issuer, clientID, clientSecret string, keySet KeySet, opts ...KeycloakOption) (p *KeycloakProvider, err error) {
	p = &KeycloakProvider{
		_client: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(p)
	}
	p.baseProvider = newBaseProvider(issuer, clientID, clientSecret, keySet, &httputil.Client{
		Client:        p._client,
		Authenticator: p,
	})
	if err := p.discover(); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *KeycloakProvider) Credentials() (issuer, clientID, clientSecret string) {
	return p.issuer, p.clientID, p.clientSecret
}

func (p *KeycloakProvider) CreateResource(request *Resource) (response *ExpandedResource, err error) {
	request.Description = ""
	if p.ownerManagedAccess {
		request.OwnerManagedAccess = true
	}
	return p.baseProvider.CreateResource(request)
}

func (p *KeycloakProvider) WWWAuthenticateDirectives() WWWAuthenticateDirectives {
	path := strings.Split(p.issuer, "/")
	return WWWAuthenticateDirectives{
		Realm: path[len(path)-1],
		AsUri: p.issuer,
	}
}

type KcPermissionLogic string

const (
	KcPositive KcPermissionLogic = "POSITIVE"
	KcNegative KcPermissionLogic = "NEGATIVE"
)

type KcPolicyDecisionStrategy string

const (
	KcUnanimous KcPolicyDecisionStrategy = "UNANIMOUS"
)

type KcPermission struct {
	ID               string                   `json:"id,omitempty"`
	Name             string                   `json:"name"`
	Type             string                   `json:"type,omitempty"`
	Description      string                   `json:"description,omitempty"`
	Logic            KcPermissionLogic        `json:"logic,omitempty"`
	DecisionStrategy KcPolicyDecisionStrategy `json:"decisionStrategy,omitempty"`
	Scopes           []string                 `json:"scopes,omitempty"`
	Owner            string                   `json:"owner,omitempty"`
	Roles            []string                 `json:"roles,omitempty"`
	Groups           []string                 `json:"groups,omitempty"`
	Clients          []string                 `json:"clients,omitempty"`
}

type kcCreatePermissionResponse struct {
	ID string `json:"id"`
}

func (p *KeycloakProvider) CreatePermissionForResource(resourceID string, perm *KcPermission) (permissionID string, err error) {
	path := fmt.Sprintf("%s/%s", p.discovery.PolicyEndpoint, resourceID)
	respObj := &kcCreatePermissionResponse{}
	if err = p.client.CreateObject(path, perm, respObj); err != nil {
		return "", err
	}
	perm.ID = respObj.ID
	return respObj.ID, nil
}

func (p *KeycloakProvider) UpdatePermission(id string, perm *KcPermission) (err error) {
	return p.client.UpdateObject(fmt.Sprintf("%s/%s", p.discovery.PolicyEndpoint, id), perm)
}

func (p *KeycloakProvider) DeletePermission(id string) (err error) {
	return p.client.DeleteObject(fmt.Sprintf("%s/%s", p.discovery.PolicyEndpoint, id))
}

func (p *KeycloakProvider) ListPermissions(urlQuery url.Values) (perms []KcPermission, err error) {
	perms = []KcPermission{}
	if err = p.client.ListObjects(p.discovery.PolicyEndpoint, urlQuery, &perms); err != nil {
		return
	}
	return perms, nil
}
