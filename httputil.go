package uma

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
)

func jsonRequest(method string, uri string, payload interface{}) (*http.Request, error) {
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

func ensure2XX(resp *http.Response) error {
	if resp.StatusCode >= 300 {
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		}
		return errUnanticipatedResponse(resp, body)
	}
	return nil
}

func (p *baseProvider) postFormUrlencoded(url string, values url.Values) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader([]byte(values.Encode())))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	if err := ensure2XX(resp); err != nil {
		return nil, err
	}
	return resp, nil
}
