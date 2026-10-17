// Package volc implements the signed JSON transport shared by Volcengine APIs.
package volc

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
	"strconv"
	"strings"
	"time"

	"github.com/rainchen537/dnsgo"
)

type Client struct {
	KeyID, Secret             string
	Endpoint, Service, Region string
	Version                   string
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

func canonicalQuery(values url.Values) string {
	return strings.ReplaceAll(values.Encode(), "+", "%20")
}

func (c *Client) Call(ctx context.Context, method, action string, input any, output any) error {
	if c.KeyID == "" || c.Secret == "" || c.Service == "" || c.Region == "" || c.Version == "" || c.Endpoint == "" {
		return &dnsgo.Error{Provider: c.Service, Operation: action, Code: dnsgo.CodeInvalidInput, Message: "incomplete Volcengine client configuration"}
	}
	endpoint := c.Endpoint
	if !strings.Contains(endpoint, "://") {
		endpoint = "https://" + endpoint
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" || parsed.Scheme != "https" && parsed.Scheme != "http" {
		return &dnsgo.Error{Provider: c.Service, Operation: action, Code: dnsgo.CodeInvalidInput, Message: "invalid endpoint"}
	}
	query := url.Values{"Action": {action}, "Version": {c.Version}}
	var payload []byte
	if method == http.MethodGet {
		values, ok := input.(map[string]any)
		if input != nil && !ok {
			return &dnsgo.Error{Provider: c.Service, Operation: action, Code: dnsgo.CodeInvalidInput, Message: "GET parameters must be a map"}
		}
		for key, value := range values {
			if value == nil {
				continue
			}
			query.Set(key, scalar(value))
		}
	} else {
		cleaned := input
		if values, ok := input.(map[string]any); ok {
			clean := map[string]any{}
			for key, value := range values {
				if value != nil {
					clean[key] = value
				}
			}
			if len(clean) == 0 {
				cleaned = nil
			} else {
				cleaned = clean
			}
		}
		if cleaned != nil {
			payload, err = json.Marshal(cleaned)
			if err != nil {
				return &dnsgo.Error{Provider: c.Service, Operation: action, Code: dnsgo.CodeInvalidInput, Cause: err}
			}
		}
	}
	now := time.Now().UTC()
	xdate := now.Format("20060102T150405Z")
	shortDate := now.Format("20060102")
	headers := map[string]string{"host": parsed.Host, "x-date": xdate}
	if len(payload) > 0 {
		headers["content-type"] = "application/json"
	}
	headerNames := make([]string, 0, len(headers))
	for key := range headers {
		headerNames = append(headerNames, key)
	}
	sort.Strings(headerNames)
	var canonicalHeaders strings.Builder
	for _, key := range headerNames {
		canonicalHeaders.WriteString(key + ":" + strings.TrimSpace(headers[key]) + "\n")
	}
	signedHeaders := strings.Join(headerNames, ";")
	canonical := method + "\n/\n" + canonicalQuery(query) + "\n" + canonicalHeaders.String() + "\n" + signedHeaders + "\n" + hashHex(payload)
	scope := shortDate + "/" + c.Region + "/" + c.Service + "/request"
	toSign := "HMAC-SHA256\n" + xdate + "\n" + scope + "\n" + hashHex([]byte(canonical))
	key := hmac256([]byte(c.Secret), shortDate)
	key = hmac256(key, c.Region)
	key = hmac256(key, c.Service)
	key = hmac256(key, "request")
	signature := hex.EncodeToString(hmac256(key, toSign))
	authorization := "HMAC-SHA256 Credential=" + c.KeyID + "/" + scope + ", SignedHeaders=" + signedHeaders + ", Signature=" + signature
	parsed.Path = "/"
	parsed.RawQuery = canonicalQuery(query)
	req, err := http.NewRequestWithContext(ctx, method, parsed.String(), bytes.NewReader(payload))
	if err != nil {
		return &dnsgo.Error{Provider: c.Service, Operation: action, Code: dnsgo.CodeInvalidInput, Message: "invalid request"}
	}
	for key, value := range headers {
		req.Header.Set(key, value)
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
		return &dnsgo.Error{Provider: c.Service, Operation: action, Code: code, Message: "request failed"}
	}
	defer response.Body.Close()
	var envelope struct {
		Metadata struct {
			RequestID string       `json:"RequestId"`
			Error     *vendorError `json:"Error"`
		} `json:"ResponseMetadata"`
		Error   *vendorError    `json:"Error"`
		Result  json.RawMessage `json:"Result"`
		Message string          `json:"Message"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 8<<20)).Decode(&envelope); err != nil {
		return &dnsgo.Error{Provider: c.Service, Operation: action, Code: dnsgo.CodeResultUnknown, Message: "invalid provider response"}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || envelope.Metadata.Error != nil || envelope.Error != nil {
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
		e := &dnsgo.Error{Provider: c.Service, Operation: action, Code: code, RequestID: envelope.Metadata.RequestID, Message: envelope.Message}
		vendor := envelope.Metadata.Error
		if vendor == nil {
			vendor = envelope.Error
		}
		if vendor != nil {
			e.VendorCode = vendor.Code
			e.Message = vendor.MessageCN
			if e.Message == "" {
				e.Message = vendor.Message
			}
		}
		return e
	}
	if output != nil && len(envelope.Result) > 0 && string(envelope.Result) != "null" {
		if err := json.Unmarshal(envelope.Result, output); err != nil {
			return &dnsgo.Error{Provider: c.Service, Operation: action, Code: dnsgo.CodeResultUnknown, Message: "invalid provider result"}
		}
	}
	return nil
}

type vendorError struct {
	Code      string `json:"Code"`
	Message   string `json:"Message"`
	MessageCN string `json:"MessageCN"`
}

func scalar(value any) string {
	switch x := value.(type) {
	case string:
		return x
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case uint64:
		return strconv.FormatUint(x, 10)
	case bool:
		if x {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}
