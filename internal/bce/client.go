// Package bce implements the Baidu Cloud BCE signed request transport.
package bce

import (
	"bytes"
	"context"
	"crypto/hmac"
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
	KeyID, Secret string
	Endpoint      string
	HTTP          *http.Client
}

func escape(value string) string {
	return strings.ReplaceAll(url.QueryEscape(value), "+", "%20")
}

func hmacHex(key []byte, value string) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

func (c *Client) Call(ctx context.Context, method, path string, query url.Values, input, output any) error {
	if c.KeyID == "" || c.Secret == "" || c.Endpoint == "" {
		return &dnsgo.Error{Provider: "baidu", Operation: method, Code: dnsgo.CodeInvalidInput, Message: "incomplete BCE client configuration"}
	}
	endpoint := c.Endpoint
	if !strings.Contains(endpoint, "://") {
		endpoint = "https://" + endpoint
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" {
		return &dnsgo.Error{Provider: "baidu", Operation: method, Code: dnsgo.CodeInvalidInput, Message: "invalid BCE endpoint"}
	}
	if query == nil {
		query = url.Values{}
	}
	var payload []byte
	if input != nil {
		payload, err = json.Marshal(input)
		if err != nil {
			return &dnsgo.Error{Provider: "baidu", Operation: method, Code: dnsgo.CodeInvalidInput, Cause: err}
		}
	}
	date := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	headers := map[string]string{"host": parsed.Host, "x-bce-date": date}
	if len(payload) > 0 {
		headers["content-type"] = "application/json"
	}
	headerNames := make([]string, 0, len(headers))
	for name := range headers {
		headerNames = append(headerNames, name)
	}
	sort.Strings(headerNames)
	canonicalHeaders := []string{}
	for _, name := range headerNames {
		canonicalHeaders = append(canonicalHeaders, escape(name)+":"+escape(strings.TrimSpace(headers[name])))
	}
	canonicalQuery := []string{}
	for _, name := range sortedKeys(query) {
		if name == "authorization" {
			continue
		}
		for _, value := range query[name] {
			canonicalQuery = append(canonicalQuery, escape(name)+"="+escape(value))
		}
	}
	canonicalURI := strings.ReplaceAll(escape(path), "%2F", "/")
	if !strings.HasPrefix(canonicalURI, "/") {
		canonicalURI = "/" + canonicalURI
	}
	canonical := method + "\n" + canonicalURI + "\n" + strings.Join(canonicalQuery, "&") + "\n" + strings.Join(canonicalHeaders, "\n")
	authString := "bce-auth-v1/" + c.KeyID + "/" + date + "/1800"
	signingKey := hmacHex([]byte(c.Secret), authString)
	signature := hmacHex([]byte(signingKey), canonical)
	authorization := authString + "/" + strings.Join(headerNames, ";") + "/" + signature
	parsed.Path = path
	parsed.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, method, parsed.String(), bytes.NewReader(payload))
	if err != nil {
		return &dnsgo.Error{Provider: "baidu", Operation: method, Code: dnsgo.CodeInvalidInput, Message: "invalid request"}
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
		return &dnsgo.Error{Provider: "baidu", Operation: method, Code: code, Message: "request failed"}
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		return &dnsgo.Error{Provider: "baidu", Operation: method, Code: dnsgo.CodeResultUnknown, Message: "response read failed"}
	}
	var problem struct {
		Code    json.RawMessage `json:"code"`
		Message string          `json:"message"`
	}
	_ = json.Unmarshal(body, &problem)
	if response.StatusCode < 200 || response.StatusCode >= 300 || len(problem.Code) > 0 && problem.Message != "" {
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
		return &dnsgo.Error{Provider: "baidu", Operation: method, Code: code,
			VendorCode: strings.Trim(string(problem.Code), "\""), Message: problem.Message}
	}
	if output != nil && len(body) > 0 {
		if err := json.Unmarshal(body, output); err != nil {
			return &dnsgo.Error{Provider: "baidu", Operation: method, Code: dnsgo.CodeResultUnknown, Message: "invalid provider result"}
		}
	}
	return nil
}

func sortedKeys(values url.Values) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
