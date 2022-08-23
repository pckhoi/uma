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
	Rsid   string   `json:"rsid,omitempty"`
	Rsname string   `json:"rsname,omitempty"`
	Scopes []string `json:"scopes,omitempty"`
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

func (tok *RPT) IsValid(resourceID, scope string, disableTokenExpirationCheck bool) bool {
	if !disableTokenExpirationCheck {
		iat := time.Unix(int64(tok.Iat), 0)
		exp := time.Unix(int64(tok.Exp), 0)
		now := time.Now()
		if !now.After(iat) || !now.Before(exp) {
			return false
		}
	}
	for _, p := range tok.Authorization.Permissions {
		if p.Rsid == resourceID {
			for _, s := range p.Scopes {
				if s == scope {
					return true
				}
			}
		}
	}
	return false
}

type AuthorizeMiddlewareOptions struct {
	GetProvider                    ProviderGetter
	IncludeScopeInPermissionTicket bool
	DisableTokenExpirationCheck    bool
}

func askForTicket(w http.ResponseWriter, p Provider, resource *Resource, scope string, opts AuthorizeMiddlewareOptions) {
	var ticket string
	var err error
	if opts.IncludeScopeInPermissionTicket {
		ticket, err = p.CreatePermissionTicket(resource.ID, scope)
	} else {
		ticket, err = p.CreatePermissionTicket(resource.ID)
	}
	if err != nil {
		panic(err)
	}
	directives := p.WWWAuthenticateDirectives()
	w.Header().Set("WWW-Authenticate",
		fmt.Sprintf(`UMA realm=%q, as_uri=%q, ticket=%q`, directives.Realm, directives.AsUri, ticket),
	)
	w.WriteHeader(http.StatusUnauthorized)
}

func AuthorizeMiddleware(opts AuthorizeMiddlewareOptions) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resource := GetResource(r)
			p := opts.GetProvider(r)
			scope := GetScope(r)
			if resource == nil || scope == "" {
				next.ServeHTTP(w, r)
				return
			}
			token := getBearerToken(r)
			if token == "" {
				askForTicket(w, p, resource, scope, opts)
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
			if rpt.IsValid(resource.ID, scope, opts.DisableTokenExpirationCheck) {
				next.ServeHTTP(w, r)
				return
			}
			askForTicket(w, p, resource, scope, opts)
		})
	}
}
