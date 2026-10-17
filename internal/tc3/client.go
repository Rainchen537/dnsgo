// Package tc3 implements Tencent Cloud's shared signed JSON transport.
package tc3

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rainchen537/dnsgo"
)

type Client struct {
	KeyID, Secret            string
	Service, Version, Region string
	Endpoint                 string
	HTTP                     *http.Client
}

func hmacSHA256(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func (c *Client) Call(ctx context.Context, action string, input any, output any) error {
	if c.KeyID == "" || c.Secret == "" || c.Service == "" || c.Version == "" || c.Endpoint == "" {
		return &dnsgo.Error{Provider: c.Service, Operation: action, Code: dnsgo.CodeInvalidInput, Message: "incomplete Tencent Cloud client configuration"}
	}
	payload, err := json.Marshal(input)
	if err != nil {
		return &dnsgo.Error{Provider: c.Service, Operation: action, Code: dnsgo.CodeInvalidInput, Cause: err}
	}
	if input == nil {
		payload = []byte("{}")
	}
	endpoint := c.Endpoint
	if !strings.Contains(endpoint, "://") {
		endpoint = "https://" + endpoint
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" {
		return &dnsgo.Error{Provider: c.Service, Operation: action, Code: dnsgo.CodeInvalidInput, Message: "invalid endpoint"}
	}
	parsed.Path = "/"
	parsed.RawQuery = ""
	host := parsed.Host
	timestamp := time.Now().UTC()
	date := timestamp.Format("2006-01-02")
	contentType := "application/json; charset=utf-8"
	canonical := "POST\n/\n\ncontent-type:" + contentType + "\nhost:" + host + "\n\ncontent-type;host\n" + sha256Hex(payload)
	scope := date + "/" + c.Service + "/tc3_request"
	toSign := "TC3-HMAC-SHA256\n" + fmt.Sprint(timestamp.Unix()) + "\n" + scope + "\n" + sha256Hex([]byte(canonical))
	secretDate := hmacSHA256([]byte("TC3"+c.Secret), date)
	secretService := hmacSHA256(secretDate, c.Service)
	secretSigning := hmacSHA256(secretService, "tc3_request")
	signature := hex.EncodeToString(hmacSHA256(secretSigning, toSign))
	authorization := "TC3-HMAC-SHA256 Credential=" + c.KeyID + "/" + scope + ", SignedHeaders=content-type;host, Signature=" + signature
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, parsed.String(), bytes.NewReader(payload))
	if err != nil {
		return &dnsgo.Error{Provider: c.Service, Operation: action, Code: dnsgo.CodeInvalidInput, Cause: err}
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", authorization)
	req.Header.Set("X-TC-Action", action)
	req.Header.Set("X-TC-Timestamp", fmt.Sprint(timestamp.Unix()))
	req.Header.Set("X-TC-Version", c.Version)
	if c.Region != "" {
		req.Header.Set("X-TC-Region", c.Region)
	}
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	response, err := httpClient.Do(req)
	if err != nil {
		return &dnsgo.Error{Provider: c.Service, Operation: action, Code: dnsgo.CodeResultUnknown, Cause: err}
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return &dnsgo.Error{Provider: c.Service, Operation: action, Code: dnsgo.CodeResultUnknown, Cause: err}
	}
	var envelope struct {
		Response json.RawMessage `json:"Response"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return &dnsgo.Error{Provider: c.Service, Operation: action, Code: dnsgo.CodeResultUnknown, Message: "invalid provider response", Cause: err}
	}
	var status struct {
		RequestID string                          `json:"RequestId"`
		Error     *struct{ Code, Message string } `json:"Error"`
	}
	if err := json.Unmarshal(envelope.Response, &status); err != nil {
		return &dnsgo.Error{Provider: c.Service, Operation: action, Code: dnsgo.CodeResultUnknown, Message: "invalid provider result", Cause: err}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || status.Error != nil {
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
		if response.StatusCode == http.StatusRequestTimeout || response.StatusCode >= http.StatusInternalServerError {
			code = dnsgo.CodeResultUnknown
		}
		e := &dnsgo.Error{Provider: c.Service, Operation: action, Code: code, RequestID: status.RequestID}
		if status.Error != nil {
			e.VendorCode = status.Error.Code
			e.Message = status.Error.Message
		}
		return e
	}
	if output != nil {
		if err := json.Unmarshal(envelope.Response, output); err != nil {
			return &dnsgo.Error{Provider: c.Service, Operation: action, Code: dnsgo.CodeResultUnknown, Message: "invalid provider result", Cause: err}
		}
	}
	return nil
}
