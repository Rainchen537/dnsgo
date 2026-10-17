// Package huaweicloud implements the SDK-HMAC-SHA256 request transport.
package huaweicloud

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

func escape(value string) string { return strings.ReplaceAll(url.QueryEscape(value), "+", "%20") }

func canonicalURI(path string) string {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		parts[i] = escape(part)
	}
	uri := strings.Join(parts, "/")
	if !strings.HasPrefix(uri, "/") {
		uri = "/" + uri
	}
	if !strings.HasSuffix(uri, "/") {
		uri += "/"
	}
	return uri
}

func hashHex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func (c *Client) Call(ctx context.Context, method, path string, query url.Values, input, output any) error {
	if c.KeyID == "" || c.Secret == "" || c.Endpoint == "" {
		return &dnsgo.Error{Provider: "huawei", Operation: method, Code: dnsgo.CodeInvalidInput, Message: "incomplete Huawei Cloud client configuration"}
	}
	endpoint := c.Endpoint
	if !strings.Contains(endpoint, "://") {
		endpoint = "https://" + endpoint
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" {
		return &dnsgo.Error{Provider: "huawei", Operation: method, Code: dnsgo.CodeInvalidInput, Message: "invalid endpoint"}
	}
	if query == nil {
		query = url.Values{}
	}
	var payload []byte
	if input != nil {
		payload, err = json.Marshal(input)
		if err != nil {
			return &dnsgo.Error{Provider: "huawei", Operation: method, Code: dnsgo.CodeInvalidInput, Cause: err}
		}
	}
	date := time.Now().UTC().Format("20060102T150405Z")
	headers := map[string]string{"host": parsed.Host, "x-sdk-date": date}
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
	queryParts := []string{}
	queryNames := make([]string, 0, len(query))
	for name := range query {
		queryNames = append(queryNames, name)
	}
	sort.Strings(queryNames)
	for _, name := range queryNames {
		for _, value := range query[name] {
			queryParts = append(queryParts, escape(name)+"="+escape(value))
		}
	}
	canonical := method + "\n" + canonicalURI(path) + "\n" + strings.Join(queryParts, "&") + "\n" +
		canonicalHeaders.String() + "\n" + strings.Join(names, ";") + "\n" + hashHex(payload)
	toSign := "SDK-HMAC-SHA256\n" + date + "\n" + hashHex([]byte(canonical))
	mac := hmac.New(sha256.New, []byte(c.Secret))
	_, _ = mac.Write([]byte(toSign))
	authorization := "SDK-HMAC-SHA256 Access=" + c.KeyID + ", SignedHeaders=" + strings.Join(names, ";") + ", Signature=" + hex.EncodeToString(mac.Sum(nil))
	parsed.Path = path
	parsed.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, method, parsed.String(), bytes.NewReader(payload))
	if err != nil {
		return &dnsgo.Error{Provider: "huawei", Operation: method, Code: dnsgo.CodeInvalidInput, Message: "invalid request"}
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
		return &dnsgo.Error{Provider: "huawei", Operation: method, Code: code, Message: "request failed"}
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		return &dnsgo.Error{Provider: "huawei", Operation: method, Code: dnsgo.CodeResultUnknown, Message: "response read failed"}
	}
	if len(body) == 0 && response.StatusCode >= 200 && response.StatusCode < 300 {
		return nil
	}
	var problem struct {
		ErrorMsg string `json:"error_msg"`
		Message  string `json:"message"`
		Error    struct {
			ErrorMsg string `json:"error_msg"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &problem)
	if response.StatusCode < 200 || response.StatusCode >= 300 || problem.ErrorMsg != "" || problem.Error.ErrorMsg != "" {
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
		message := problem.ErrorMsg
		if message == "" {
			message = problem.Error.ErrorMsg
		}
		if message == "" {
			message = problem.Message
		}
		return &dnsgo.Error{Provider: "huawei", Operation: method, Code: code, Message: message}
	}
	if output != nil {
		if err := json.Unmarshal(body, output); err != nil {
			return &dnsgo.Error{Provider: "huawei", Operation: method, Code: dnsgo.CodeResultUnknown, Message: "invalid provider result"}
		}
	}
	return nil
}
