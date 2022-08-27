package uma

import (
	"context"
	"net/http"
	"time"
)

type Permission struct {
	Rsid   string   `json:"rsid,omitempty"`
	Rsname string   `json:"rsname,omitempty"`
	Scopes []string `json:"scopes,omitempty"`
}

type Authorization struct {
	Permissions []Permission `json:"permissions,omitempty"`
}

type Claims struct {
	Authorization     *Authorization `json:"authorization,omitempty"`
	Email             string         `json:"email,omitempty"`
	Name              string         `json:"name,omitempty"`
	GivenName         string         `json:"given_name,omitempty"`
	FamilyName        string         `json:"family_name,omitempty"`
	PreferredUsername string         `json:"preferred_username,omitempty"`
	EmailVerified     bool           `json:"email_verified,omitempty"`
	Aud               string         `json:"aud,omitempty"`
	Sid               string         `json:"sid,omitempty"`
	Jti               string         `json:"jti,omitempty"`
	Exp               int            `json:"exp,omitempty"`
	Nbf               int            `json:"nbf,omitempty"`
	Iat               int            `json:"iat,omitempty"`
	Sub               string         `json:"sub,omitempty"`
	Typ               string         `json:"typ,omitempty"`
	Azp               string         `json:"azp,omitempty"`
}

func stringSet(sl []string) map[string]struct{} {
	m := map[string]struct{}{}
	for _, s := range sl {
		m[s] = struct{}{}
	}
	return m
}

func (tok *Claims) IsValid(resourceID string, disableTokenExpirationCheck bool, scopes ...string) bool {
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
			m := stringSet(p.Scopes)
			for _, s := range scopes {
				if _, ok := m[s]; !ok {
					return false
				}
			}
			return true
		}
	}
	return false
}

type claimsKey struct{}

func setClaims(r *http.Request, ur *Claims) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), claimsKey{}, ur))
}

// GetClaims returns claims from Requesting Party Token
func GetClaims(r *http.Request) *Claims {
	if v := r.Context().Value(claimsKey{}); v != nil {
		return v.(*Claims)
	}
	return nil
}
