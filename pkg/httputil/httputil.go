package httputil

import (
	"bytes"
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
