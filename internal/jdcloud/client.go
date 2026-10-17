// Package jdcloud implements the JDCLOUD2 signed JSON request transport.
package jdcloud

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/rainchen537/dnsgo"
)

type Client struct {
	KeyID, Secret             string
	Endpoint, Service, Region string
	HTTP                      *http.Client
}

func hmac256(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func hashHex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func escape(value string) string { return strings.ReplaceAll(url.QueryEscape(value), "+", "%20") }

func (c *Client) Call(ctx context.Context, method, path string, query url.Values, input, output any) error {
	if c.KeyID == "" || c.Secret == "" || c.Endpoint == "" || c.Service == "" || c.Region == "" {
		return &dnsgo.Error{Provider: "jdcloud", Operation: method, Code: dnsgo.CodeInvalidInput, Message: "incomplete JDCloud client configuration"}
	}
	endpoint := c.Endpoint
	if !strings.Contains(endpoint, "://") {
		endpoint = "https://" + endpoint
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" {
		return &dnsgo.Error{Provider: "jdcloud", Operation: method, Code: dnsgo.CodeInvalidInput, Message: "invalid endpoint"}
	}
	if query == nil {
		query = url.Values{}
	}
	var payload []byte
	if input != nil {
		payload, err = json.Marshal(input)
		if err != nil {
			return &dnsgo.Error{Provider: "jdcloud", Operation: method, Code: dnsgo.CodeInvalidInput, Cause: err}
		}
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return &dnsgo.Error{Provider: "jdcloud", Operation: method, Code: dnsgo.CodeTransport, Cause: err}
	}
	date := time.Now().UTC().Format("20060102T150405Z")
	headers := map[string]string{"host": parsed.Host, "x-jdcloud-algorithm": "JDCLOUD2-HMAC-SHA256",
		"x-jdcloud-date": date, "x-jdcloud-nonce": hex.EncodeToString(nonce)}
	if len(payload) > 0 {
		headers["content-type"] = "application/json"
	}
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	var canonicalHeaders strings.Builder
	for _, name := range names {
		canonicalHeaders.WriteString(name + ":" + strings.TrimSpace(headers[name]) + "\n")
	}
	queryNames := make([]string, 0, len(query))
	for name := range query {
		queryNames = append(queryNames, name)
	}
	sort.Strings(queryNames)
	queryParts := []string{}
	for _, name := range queryNames {
		for _, value := range query[name] {
			queryParts = append(queryParts, escape(name)+"="+escape(value))
		}
	}
	signedHeaders := strings.Join(names, ";")
	canonical := method + "\n" + path + "\n" + strings.Join(queryParts, "&") + "\n" +
		canonicalHeaders.String() + "\n" + signedHeaders + "\n" + hashHex(payload)
	scope := date[:8] + "/" + c.Region + "/" + c.Service + "/jdcloud2_request"
	toSign := "JDCLOUD2-HMAC-SHA256\n" + date + "\n" + scope + "\n" + hashHex([]byte(canonical))
	key := hmac256([]byte("JDCLOUD2"+c.Secret), date[:8])
	key = hmac256(key, c.Region)
	key = hmac256(key, c.Service)
	key = hmac256(key, "jdcloud2_request")
	signature := hex.EncodeToString(hmac256(key, toSign))
	authorization := "JDCLOUD2-HMAC-SHA256 Credential=" + c.KeyID + "/" + scope + ", SignedHeaders=" + signedHeaders + ", Signature=" + signature
	parsed.Path = path
	parsed.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, method, parsed.String(), bytes.NewReader(payload))
	if err != nil {
		return &dnsgo.Error{Provider: "jdcloud", Operation: method, Code: dnsgo.CodeInvalidInput, Message: "invalid request"}
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	req.Header.Set("Authorization", authorization)
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
		return &dnsgo.Error{Provider: "jdcloud", Operation: method, Code: code, Message: "request failed"}
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		return &dnsgo.Error{Provider: "jdcloud", Operation: method, Code: dnsgo.CodeResultUnknown, Message: "response read failed"}
	}
	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return &dnsgo.Error{Provider: "jdcloud", Operation: method, Code: dnsgo.CodeResultUnknown, Message: "invalid provider response"}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || envelope.Error.Message != "" {
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
		return &dnsgo.Error{Provider: "jdcloud", Operation: method, Code: code, Message: envelope.Error.Message}
	}
	if output != nil {
		result := envelope.Result
		if len(result) == 0 {
			result = body
		}
		if err := json.Unmarshal(result, output); err != nil {
			return &dnsgo.Error{Provider: "jdcloud", Operation: method, Code: dnsgo.CodeResultUnknown, Message: "invalid provider result"}
		}
	}
	return nil
}
