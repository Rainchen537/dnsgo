// Package ucloud implements the signed UCloud JSON API transport.
package ucloud

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/rainchen537/dnsgo"
)

type Client struct {
	PublicKey, PrivateKey string
	Endpoint              string
	HTTP                  *http.Client
}

func (c *Client) Call(ctx context.Context, action string, params map[string]any, output any) error {
	if c.PublicKey == "" || c.PrivateKey == "" {
		return &dnsgo.Error{Provider: "ucloud", Operation: action, Code: dnsgo.CodeInvalidInput, Message: "public and private keys are required"}
	}
	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = "https://api.ucloud.cn/"
	}
	if !strings.HasPrefix(endpoint, "https://") {
		return &dnsgo.Error{Provider: "ucloud", Operation: action, Code: dnsgo.CodeInvalidInput, Message: "UCloud endpoint must use HTTPS"}
	}
	input := map[string]any{"Action": action, "PublicKey": c.PublicKey}
	for key, value := range params {
		input[key] = value
	}
	keys := make([]string, 0, len(input))
	for key := range input {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var signing strings.Builder
	for _, key := range keys {
		signing.WriteString(key)
		signing.WriteString(fmt.Sprint(input[key]))
	}
	signing.WriteString(c.PrivateKey)
	digest := sha1.Sum([]byte(signing.String()))
	input["Signature"] = hex.EncodeToString(digest[:])
	data, err := json.Marshal(input)
	if err != nil {
		return &dnsgo.Error{Provider: "ucloud", Operation: action, Code: dnsgo.CodeInvalidInput, Cause: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return &dnsgo.Error{Provider: "ucloud", Operation: action, Code: dnsgo.CodeInvalidInput, Message: "invalid request"}
	}
	req.Header.Set("Content-Type", "application/json")
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
	}
	response, err := httpClient.Do(req)
	if err != nil {
		return &dnsgo.Error{Provider: "ucloud", Operation: action, Code: dnsgo.CodeResultUnknown, Message: "request failed"}
	}
	defer response.Body.Close()
	var result struct {
		RetCode *int   `json:"RetCode"`
		Message string `json:"Message"`
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		return &dnsgo.Error{Provider: "ucloud", Operation: action, Code: dnsgo.CodeResultUnknown, Message: "response read failed"}
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return &dnsgo.Error{Provider: "ucloud", Operation: action, Code: dnsgo.CodeResultUnknown, Message: "invalid provider response"}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || result.RetCode == nil || *result.RetCode != 0 {
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
		return &dnsgo.Error{Provider: "ucloud", Operation: action, Code: code, Message: result.Message}
	}
	if output != nil {
		if err := json.Unmarshal(body, output); err != nil {
			return &dnsgo.Error{Provider: "ucloud", Operation: action, Code: dnsgo.CodeResultUnknown, Message: "invalid provider result"}
		}
	}
	return nil
}
