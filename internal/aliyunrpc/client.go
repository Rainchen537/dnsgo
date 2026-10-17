// Package aliyunrpc implements Aliyun RPC HMAC-SHA1 requests used by CAS.
package aliyunrpc

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rainchen537/dnsgo"
)

type Client struct {
	KeyID, Secret     string
	Endpoint, Version string
	HTTP              *http.Client
}

func escape(value string) string { return strings.ReplaceAll(url.QueryEscape(value), "+", "%20") }

func (c *Client) Call(ctx context.Context, method, action string, params url.Values, output any) error {
	if c.KeyID == "" || c.Secret == "" || c.Endpoint == "" || c.Version == "" {
		return &dnsgo.Error{Provider: "aliyun", Operation: action, Code: dnsgo.CodeInvalidInput, Message: "incomplete Aliyun RPC configuration"}
	}
	if params == nil {
		params = url.Values{}
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return &dnsgo.Error{Provider: "aliyun", Operation: action, Code: dnsgo.CodeTransport, Cause: err}
	}
	for key, value := range map[string]string{
		"Action": action, "Format": "JSON", "Version": c.Version, "AccessKeyId": c.KeyID,
		"SignatureMethod": "HMAC-SHA1", "SignatureVersion": "1.0", "SignatureNonce": hex.EncodeToString(nonce),
		"Timestamp": time.Now().UTC().Format(time.RFC3339),
	} {
		params.Set(key, value)
	}
	canonical := strings.ReplaceAll(params.Encode(), "+", "%20")
	mac := hmac.New(sha1.New, []byte(c.Secret+"&"))
	_, _ = mac.Write([]byte(method + "&%2F&" + escape(canonical)))
	params.Set("Signature", base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	endpoint := strings.TrimRight(c.Endpoint, "/") + "/"
	var body io.Reader
	if method == http.MethodGet {
		endpoint += "?" + params.Encode()
	} else {
		body = strings.NewReader(params.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return &dnsgo.Error{Provider: "aliyun", Operation: action, Code: dnsgo.CodeInvalidInput, Message: "invalid request"}
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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
		return &dnsgo.Error{Provider: "aliyun", Operation: action, Code: code, Message: "request failed"}
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		return &dnsgo.Error{Provider: "aliyun", Operation: action, Code: dnsgo.CodeResultUnknown, Message: "response read failed"}
	}
	var envelope struct {
		Code      string `json:"Code"`
		Message   string `json:"Message"`
		RequestID string `json:"RequestId"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return &dnsgo.Error{Provider: "aliyun", Operation: action, Code: dnsgo.CodeResultUnknown, Message: "invalid provider response"}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || envelope.Code != "" {
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
		return &dnsgo.Error{Provider: "aliyun", Operation: action, Code: code, VendorCode: envelope.Code,
			RequestID: envelope.RequestID, Message: envelope.Message}
	}
	if output != nil {
		if err := json.Unmarshal(data, output); err != nil {
			return &dnsgo.Error{Provider: "aliyun", Operation: action, Code: dnsgo.CodeResultUnknown, Message: "invalid provider result"}
		}
	}
	return nil
}
