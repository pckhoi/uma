package uma

import (
	"io"
	"net/http"
	"time"

	"github.com/pckhoi/uma/pkg/httputil"
)

type ClientCreds struct {
	AccessToken      string `json:"access_token,omitempty"`
	ExpiresIn        int    `json:"expires_in,omitempty"`
	RefreshExpiresIn int    `json:"refresh_expires_in,omitempty"`
	RefreshToken     string `json:"refresh_token,omitempty"`
	TokenType        string `json:"token_type,omitempty"`
	IdToken          string `json:"id_token,omitempty"`
	NotBeforePolicy  int    `json:"not-before-policy,omitempty"`
	SessionState     string `json:"session_state,omitempty"`

	expiresTime        time.Time
	refreshExpiresTime time.Time
}

func (c *ClientCreds) setExpiresTime() {
	if c.expiresTime.IsZero() {
		c.expiresTime = time.Now().Add(time.Second * time.Duration(c.ExpiresIn))
		c.refreshExpiresTime = time.Now().Add(time.Second * time.Duration(c.RefreshExpiresIn))
	}
}

func (c *ClientCreds) expired() bool {
	return c.expiresTime.Before(time.Now())
}

func (c *ClientCreds) refreshExpired() bool {
	return c.refreshExpiresTime.Before(time.Now())
}

func (p *baseProvider) doRequest(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer "+p.ClientCreds.AccessToken)
	return p.client.Do(req)
}

func (p *baseProvider) DoRequest(req *http.Request) (*http.Response, error) {
	if p.ClientCreds == nil {
		if err := p.authenticateClient(); err != nil {
			return nil, err
		}
		return p.doRequest(req)
	}
	resp, err := p.doRequest(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		if p.ClientCreds.expired() {
			if p.ClientCreds.refreshExpired() {
				if err := p.authenticateClient(); err != nil {
					return nil, err
				}
			} else {
				if err := p.refreshClient(); err != nil {
					return nil, err
				}
			}
			return p.doRequest(req)
		} else {
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}
			return nil, httputil.ErrUnanticipatedResponse(resp, body)
		}
	}
	return resp, nil
}

func (p *baseProvider) authenticateClient() error {
	resp, err := httputil.PostFormUrlencoded(p.client, p.UMADiscovery.TokenEndpoint, nil, map[string][]string{
		"grant_type":    {"client_credentials"},
		"client_id":     {p.ClientID},
		"client_secret": {p.ClientSecret},
	})
	if err != nil {
		return err
	}
	p.ClientCreds = &ClientCreds{}
	if err = httputil.DecodeJSONResponse(resp, p.ClientCreds); err != nil {
		return err
	}
	p.ClientCreds.setExpiresTime()
	return nil
}

func (p *baseProvider) refreshClient() error {
	resp, err := httputil.PostFormUrlencoded(p.client, p.UMADiscovery.TokenEndpoint, nil, map[string][]string{
		"grant_type":    {"refresh_token"},
		"client_id":     {p.ClientID},
		"refresh_token": {p.ClientCreds.RefreshToken},
	})
	if err != nil {
		return err
	}
	p.ClientCreds = &ClientCreds{}
	if err = httputil.DecodeJSONResponse(resp, p.ClientCreds); err != nil {
		return err
	}
	p.ClientCreds.setExpiresTime()
	return nil
}
