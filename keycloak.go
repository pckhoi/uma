package uma

import "strings"

type keycloakProvider struct {
	*baseProvider
}

func (p *keycloakProvider) Realm() string {
	path := strings.Split(p.Issuer, "/")
	return path[len(path)-1]
}
