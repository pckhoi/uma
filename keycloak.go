package uma

import "strings"

type keycloakProvider struct {
	*baseProvider
}

func (p *keycloakProvider) Realm() string {
	path := strings.Split(p.Issuer, "/")
	return path[len(path)-1]
}

type kcError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func (p *keycloakProvider) RegisterResource(resource *Resource) (err error) {
	resource.Description = ""
	return p.baseProvider.RegisterResource(resource)
}
