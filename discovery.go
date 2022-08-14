package uma

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type UMADiscovery struct {
	TokenEndpoint                string `json:"token_endpoint,omitempty"`
	TokenIntrospectionEndpoint   string `json:"token_introspection_endpoint,omitempty"`
	ResourceRegistrationEndpoint string `json:"resource_registration_endpoint,omitempty"`
	PermissionEndpoint           string `json:"permission_endpoint,omitempty"`
	PolicyEndpoint               string `json:"policy_endpoint,omitempty"`
}

func errUnanticipatedResponse(resp *http.Response, body []byte) error {
	return fmt.Errorf(
		"unanticipated response %d: (%s) %s",
		resp.StatusCode, resp.Header.Get("Content-Type"), string(body),
	)
}

func decodeJSONResponse(resp *http.Response, obj interface{}) error {
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if !strings.Contains(resp.Header.Get("Content-Type"), "application/json") || resp.StatusCode >= 300 {
		return errUnanticipatedResponse(resp, body)
	}
	return json.Unmarshal(body, obj)
}

func (p *baseProvider) DiscoverUMA() error {
	resp, err := http.DefaultClient.Get(p.Issuer + "/.well-known/uma2-configuration")
	if err != nil {
		return err
	}
	doc := &UMADiscovery{}
	if err = decodeJSONResponse(resp, doc); err != nil {
		return err
	}
	p.UMADiscovery = *doc
	return nil
}
