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
	if !strings.Contains(resp.Header.Get("Content-Type"), "application/json") || resp.StatusCode >= 300 {
		return NewErrUnanticipatedResponse(resp)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, obj)
}

func GetRedirectLocation(resp *http.Response) (loc *url.URL, err error) {
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently || resp.StatusCode == http.StatusTemporaryRedirect {
		return url.Parse(resp.Header.Get("Location"))
	}
	return nil, NewErrUnanticipatedResponse(resp)
}

type ErrUnanticipatedResponse struct {
	Status      int
	ContentType string
	Body        string
}

func NewErrUnanticipatedResponse(resp *http.Response) *ErrUnanticipatedResponse {
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	return &ErrUnanticipatedResponse{
		Status:      resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		Body:        string(body),
	}
}

func (err ErrUnanticipatedResponse) Error() string {
	return fmt.Sprintf(
		"unanticipated response %d: (%s) %s",
		err.Status, err.ContentType, err.Body,
	)
}

func Ensure2XX(resp *http.Response) error {
	if resp.StatusCode >= 300 {
		return NewErrUnanticipatedResponse(resp)
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
