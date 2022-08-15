package uma

import (
	"net/http"

	"github.com/pckhoi/uma/pkg/httputil"
)

type UMADiscovery struct {
	TokenEndpoint                string `json:"token_endpoint,omitempty"`
	TokenIntrospectionEndpoint   string `json:"token_introspection_endpoint,omitempty"`
	ResourceRegistrationEndpoint string `json:"resource_registration_endpoint,omitempty"`
	PermissionEndpoint           string `json:"permission_endpoint,omitempty"`
	PolicyEndpoint               string `json:"policy_endpoint,omitempty"`
}

func (p *baseProvider) DiscoverUMA() error {
	resp, err := http.DefaultClient.Get(p.Issuer + "/.well-known/uma2-configuration")
	if err != nil {
		return err
	}
	doc := &UMADiscovery{}
	if err = httputil.DecodeJSONResponse(resp, doc); err != nil {
		return err
	}
	p.UMADiscovery = *doc
	return nil
}
