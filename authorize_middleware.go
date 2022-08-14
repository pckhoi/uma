package uma

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type scopeKey struct{}

func SetScope(r *http.Request, scope string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), scopeKey{}, scope))
}

func GetScope(r *http.Request) string {
	if v := r.Context().Value(scopeKey{}); v != nil {
		return v.(string)
	}
	return ""
}

func getBearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if header != "" {
		if strings.HasPrefix(header, "Bearer ") {
			return strings.TrimPrefix(header, "Bearer ")
		}
	}
	return ""
}

type Permission struct {
	ResourceSetID   string   `json:"resource_set_id,omitempty"`
	ResourceSetName string   `json:"resource_set_name,omitempty"`
	ResourceScopes  []string `json:"resource_scopes,omitempty"`
}

type Authorization struct {
	Permissions []Permission `json:"permissions,omitempty"`
}

type RPT struct {
	Authorization *Authorization `json:"authorization,omitempty"`
	Jti           string         `json:"jti"`
	Exp           int            `json:"exp"`
	Nbf           int            `json:"nbf"`
	Iat           int            `json:"iat"`
	Sub           string         `json:"sub"`
	Typ           string         `json:"typ"`
	Azp           string         `json:"azp"`
}

func (tok *RPT) IsValid(resourceID, scope string) bool {
	iat := time.Unix(int64(tok.Iat), 0)
	exp := time.Unix(int64(tok.Exp), 0)
	now := time.Now()
	if !now.After(iat) || !now.Before(exp) {
		return false
	}
	for _, p := range tok.Authorization.Permissions {
		if p.ResourceSetID == resourceID {
			for _, s := range p.ResourceScopes {
				if s == scope {
					return true
				}
			}
		}
	}
	return false
}

func AuthorizeMiddleware(includeScopeInPermissionTicket bool) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resource := GetUMAResource(r)
			p := getProvider(r)
			if resource == nil {
				next.ServeHTTP(w, r)
				return
			}
			scope := GetScope(r)
			token := getBearerToken(r)
			if token == "" {
				var ticket string
				var err error
				if includeScopeInPermissionTicket {
					ticket, err = p.RequestPermissionTicket(resource.ID, scope)
				} else {
					ticket, err = p.RequestPermissionTicket(resource.ID)
				}
				if err != nil {
					panic(err)
				}
				w.Header().Set("WWW-Authenticate",
					fmt.Sprintf(`UMA realm=%q, as_uri=%q, ticket=%q`, p.Realm(), p.AuthorizationServerURI(), ticket),
				)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			b, err := p.VerifySignature(r.Context(), token)
			if err != nil {
				panic(err)
			}
			rpt := &RPT{}
			if err = json.Unmarshal(b, rpt); err != nil {
				panic(err)
			}
			if rpt.IsValid(resource.ID, scope) {
				next.ServeHTTP(w, r)
				return
			}
			w.WriteHeader(http.StatusForbidden)
		})
	}
}
