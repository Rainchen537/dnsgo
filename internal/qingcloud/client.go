// Package qingcloud implements the signed Routewize API transport.
package qingcloud

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rainchen537/dnsgo"
)

type Client struct {
	KeyID, Secret string
	Endpoint      string
	HTTP          *http.Client
}

func (c *Client) Call(ctx context.Context, method, path string, query url.Values, input, output any) error {
	if c.KeyID == "" || c.Secret == "" || c.Endpoint == "" {
		return &dnsgo.Error{Provider: "qingcloud", Operation: method, Code: dnsgo.CodeInvalidInput, Message: "incomplete QingCloud client configuration"}
	}
	base := strings.TrimRight(c.Endpoint, "/")
	parsed, err := url.Parse(base)
	if err != nil || parsed.Host == "" || parsed.Scheme != "http" && parsed.Scheme != "https" {
		return &dnsgo.Error{Provider: "qingcloud", Operation: method, Code: dnsgo.CodeInvalidInput, Message: "invalid endpoint"}
	}
	if query == nil {
		query = url.Values{}
	}
	date := time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")
	stringToSign := method + "\n" + date + "\n" + path
	if method == http.MethodGet && len(query) > 0 {
		stringToSign += "?" + query.Encode()
	}
	mac := hmac.New(sha256.New, []byte(c.Secret))
	_, _ = mac.Write([]byte(stringToSign))
	authorization := "QC-HMAC-SHA256 " + c.KeyID + ":" + base64.StdEncoding.EncodeToString(mac.Sum(nil))
	var payload []byte
	if method != http.MethodGet && input != nil {
		payload, err = json.Marshal(input)
		if err != nil {
			return &dnsgo.Error{Provider: "qingcloud", Operation: method, Code: dnsgo.CodeInvalidInput, Cause: err}
		}
	}
	parsed.Path = path
	if method == http.MethodGet {
		parsed.RawQuery = query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, parsed.String(), bytes.NewReader(payload))
	if err != nil {
		return &dnsgo.Error{Provider: "qingcloud", Operation: method, Code: dnsgo.CodeInvalidInput, Message: "invalid request"}
	}
	req.Header.Set("Authorization", authorization)
	req.Header.Set("Date", date)
	if method != http.MethodGet {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
	}
	response, err := httpClient.Do(req)
	if err != nil {
		code := dnsgo.CodeResultUnknown
		if method == http.MethodGet {
			code = dnsgo.CodeTransport
		}
		return &dnsgo.Error{Provider: "qingcloud", Operation: method, Code: code, Message: "request failed"}
	}
	defer response.Body.Close()
	if method == http.MethodDelete && response.StatusCode == http.StatusNoContent {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		return &dnsgo.Error{Provider: "qingcloud", Operation: method, Code: dnsgo.CodeResultUnknown, Message: "response read failed"}
	}
	var envelope struct {
		Code    *int            `json:"code"`
		Message string          `json:"message"`
		Msg     string          `json:"msg"`
		Domains json.RawMessage `json:"domains"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return &dnsgo.Error{Provider: "qingcloud", Operation: method, Code: dnsgo.CodeResultUnknown, Message: "invalid provider response"}
	}
	success := response.StatusCode >= 200 && response.StatusCode < 300 &&
		(envelope.Code != nil && *envelope.Code == 0 || len(envelope.Domains) > 0)
	if !success {
		code := dnsgo.CodeProvider
		switch response.StatusCode {
		case 401:
			code = dnsgo.CodeAuthentication
		case 403:
			code = dnsgo.CodePermission
		case 404:
			code = dnsgo.CodeNotFound
		case 429:
			code = dnsgo.CodeRateLimited
		}
		if method != http.MethodGet && (response.StatusCode == http.StatusRequestTimeout || response.StatusCode >= http.StatusInternalServerError) {
			code = dnsgo.CodeResultUnknown
		}
		message := envelope.Message
		if message == "" {
			message = envelope.Msg
		}
		return &dnsgo.Error{Provider: "qingcloud", Operation: method, Code: code, Message: message}
	}
	if output != nil {
		if err := json.Unmarshal(body, output); err != nil {
			return &dnsgo.Error{Provider: "qingcloud", Operation: method, Code: dnsgo.CodeResultUnknown, Message: "invalid provider result"}
		}
	}
	return nil
}
