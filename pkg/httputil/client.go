package httputil

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/go-logr/logr"
)

type ClientCreds struct {
	AccessToken      string `json:"access_token,omitempty"`
	ExpiresIn        int    `json:"expires_in,omitempty"`
	RefreshExpiresIn int    `json:"refresh_expires_in,omitempty"`
	RefreshToken     string `json:"refresh_token,omitempty"`
	TokenType        string `json:"token_type,omitempty"`

	expiresTime time.Time
}

func (c *ClientCreds) setExpiresTime() {
	if c.expiresTime.IsZero() {
		c.expiresTime = time.Now().Add(time.Second * time.Duration(c.ExpiresIn))
	}
}

func (c *ClientCreds) expired() bool {
	return c.expiresTime.Before(time.Now())
}

type Authenticator interface {
	Authenticate(client *http.Client) (*ClientCreds, error)
}

type Client struct {
	Client        *http.Client
	creds         *ClientCreds
	Authenticator Authenticator
	Logger        logr.Logger
}

func (c *Client) doRequest(req *http.Request) (resp *http.Response, err error) {
	if c.creds != nil {
		req.Header.Set("Authorization", "Bearer "+c.creds.AccessToken)
	}
	return c.Client.Do(req)
}

func (c *Client) DoRequest(req *http.Request) (resp *http.Response, err error) {
	if c.creds == nil {
		c.Logger.Info("credentials not found")
		c.creds, err = c.Authenticator.Authenticate(c.Client)
		if err != nil {
			return nil, err
		}
		c.creds.setExpiresTime()
		return c.doRequest(req)
	}
	resp, err = c.doRequest(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		if c.creds.expired() {
			c.Logger.Info("credentials expired")
			c.creds, err = c.Authenticator.Authenticate(c.Client)
			if err != nil {
				return nil, err
			}
			c.creds.setExpiresTime()
			return c.doRequest(req)
		} else {
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}
			return nil, ErrUnanticipatedResponse(resp, body)
		}
	}
	return resp, nil
}

func PostFormUrlencoded(client *http.Client, url string, modifyRequest func(r *http.Request), values url.Values) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader([]byte(values.Encode())))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if modifyRequest != nil {
		modifyRequest(req)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if err := Ensure2XX(resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) PostFormUrlencoded(url string, modifyRequest func(r *http.Request), values url.Values) (*http.Response, error) {
	return PostFormUrlencoded(c.Client, url, modifyRequest, values)
}

func (c *Client) Get(url string) (resp *http.Response, err error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) GetObject(endpoint string, response interface{}) (err error) {
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return
	}
	resp, err := c.DoRequest(req)
	if err != nil {
		return err
	}
	if err = Ensure2XX(resp); err != nil {
		return err
	}
	return DecodeJSONResponse(resp, response)
}

func (c *Client) CreateObject(endpoint string, payload, response interface{}) (err error) {
	req, err := JSONRequest(http.MethodPost, endpoint, payload)
	if err != nil {
		return err
	}
	resp, err := c.DoRequest(req)
	if err != nil {
		return err
	}
	if err = Ensure2XX(resp); err != nil {
		return err
	}
	return DecodeJSONResponse(resp, response)
}

func (c *Client) UpdateObject(endpoint string, payload interface{}) (err error) {
	req, err := JSONRequest(http.MethodPut, endpoint, payload)
	if err != nil {
		return err
	}
	resp, err := c.DoRequest(req)
	if err != nil {
		return err
	}
	return Ensure2XX(resp)
}

func (c *Client) DeleteObject(endpoint string) (err error) {
	req, err := http.NewRequest(http.MethodDelete, endpoint, nil)
	if err != nil {
		return err
	}
	resp, err := c.DoRequest(req)
	if err != nil {
		return err
	}
	return Ensure2XX(resp)
}

func (c *Client) ListObjects(endpoint string, urlQuery url.Values, response interface{}) (err error) {
	if len(urlQuery) != 0 {
		endpoint = fmt.Sprintf("%s?%s", endpoint, urlQuery.Encode())
	}
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	resp, err := c.DoRequest(req)
	if err != nil {
		return err
	}
	if err = Ensure2XX(resp); err != nil {
		return err
	}
	return DecodeJSONResponse(resp, response)
}
