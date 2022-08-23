package httputil

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

func JSONRequest(method string, uri string, payload interface{}) (*http.Request, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(method, uri, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

func DecodeJSONResponse(resp *http.Response, obj interface{}) error {
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if !strings.Contains(resp.Header.Get("Content-Type"), "application/json") || resp.StatusCode >= 300 {
		return ErrUnanticipatedResponse(resp, body)
	}
	return json.Unmarshal(body, obj)
}

func GetRedirectLocation(resp *http.Response) (loc *url.URL, err error) {
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently || resp.StatusCode == http.StatusTemporaryRedirect {
		return url.Parse(resp.Header.Get("Location"))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return nil, ErrUnanticipatedResponse(resp, body)
}

func ErrUnanticipatedResponse(resp *http.Response, body []byte) error {
	return fmt.Errorf(
		"unanticipated response %d: (%s) %s",
		resp.StatusCode, resp.Header.Get("Content-Type"), string(body),
	)
}

func Ensure2XX(resp *http.Response) error {
	if resp.StatusCode >= 300 {
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		}
		return ErrUnanticipatedResponse(resp, body)
	}
	return nil
}

type clientKey struct{}

func WithClient(req *http.Request, client *http.Client) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), clientKey{}, client))
}

func getClient(req *http.Request) *http.Client {
	if v := req.Context().Value(clientKey{}); v != nil {
		return v.(*http.Client)
	}
	return nil
}

type acessTokenKey struct{}

func WithAccessToken(req *http.Request, token string) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), acessTokenKey{}, token))
}

func getAccessToken(req *http.Request) string {
	if v := req.Context().Value(acessTokenKey{}); v != nil {
		return v.(string)
	}
	return ""
}

func DoRequest(req *http.Request) (*http.Response, error) {
	client := getClient(req)
	if client == nil {
		client = http.DefaultClient
	}
	token := getAccessToken(req)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return client.Do(req)
}
