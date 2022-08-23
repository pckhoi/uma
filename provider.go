package uma

import (
	"context"
	"net/http"
	"net/url"

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

type WWWAuthenticateDirectives struct {
	Realm string
	AsUri string
}

type Provider interface {
	KeySet

	// Authenticate authenticates client and get an access token for permission api
	Authenticate(client *http.Client) (*httputil.ClientCreds, error)

	// CreateResource creates resource
	CreateResource(resource *Resource) (id string, err error)

	// GetResource gets resource by id
	GetResource(id string) (resource *Resource, err error)

	// UpdateResource updates resource by id
	UpdateResource(id string, resource *Resource) (err error)

	// DeleteResource delete resource by id
	DeleteResource(id string) (err error)

	// ListResources lists resources. You can add custom query parameters with urlQuery
	ListResources(urlQuery url.Values) (ids []string, err error)

	// CreatePermissionTicket creates a permission ticket based on resourceID and
	// optional scopes
	CreatePermissionTicket(resourceID string, scopes ...string) (string, error)

	WWWAuthenticateDirectives() WWWAuthenticateDirectives
}
