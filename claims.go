package uma

import (
	"context"
	"net/http"
	"time"

	"github.com/go-logr/logr"
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

func scopesAreSufficient(logger *logr.Logger, existingScopes, requiredScopes []string) bool {
	m := stringSet(existingScopes)
	for _, s := range requiredScopes {
		if _, ok := m[s]; !ok {
			if logger != nil {
				logger.Info("missing scope", "scope", s)
			}
			return false
		}
	}
	return true
}

func (tok *Claims) IsValid(logger *logr.Logger, resourceID string, disableTokenExpirationCheck bool, scopes ...string) bool {
	if !disableTokenExpirationCheck {
		iat := time.Unix(int64(tok.Iat), 0)
		exp := time.Unix(int64(tok.Exp), 0)
		now := time.Now()
		if !now.After(iat) || !now.Before(exp) {
			if logger != nil {
				logger.Info("token expired", "iat", iat, "exp", exp, "now", now)
			}
			return false
		}
	}
	if tok.Authorization != nil {
		for _, p := range tok.Authorization.Permissions {
			if p.Rsid == resourceID {
				return scopesAreSufficient(logger, p.Scopes, scopes)
			}
		}
	}
	if logger != nil {
		logger.Info("resource not found in claims", "resource_id", resourceID, "claims", tok)
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

// GetClaimsScopes check whether current RPT claims has specified scopes
// for the current resource
func GetClaimsScopes(r *http.Request) (scopes map[string]struct{}) {
	c := GetClaims(r)
	rsc := GetResource(r)
	if c == nil || c.Authorization == nil || rsc == nil {
		return
	}
	for _, p := range c.Authorization.Permissions {
		if p.Rsid == rsc.ID {
			return stringSet(p.Scopes)
		}
	}
	return
}
