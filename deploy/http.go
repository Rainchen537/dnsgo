package deploy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/rainchen537/dnsgo"
)

func certificate(material Material) (*x509.Certificate, error) {
	pair, err := tls.X509KeyPair(material.FullChainPEM, material.PrivateKeyPEM)
	if err != nil || len(pair.Certificate) == 0 {
		return nil, errors.New("certificate and private key are invalid or do not match")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, errors.New("certificate leaf cannot be parsed")
	}
	return leaf, nil
}

func certificatePEM(content []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(content)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("PEM certificate missing")
	}
	return x509.ParseCertificate(block.Bytes)
}

func targetEndpoint(config Config, defaultURL string) (string, error) {
	endpoint := strings.TrimRight(strings.TrimSpace(config.Endpoint), "/")
	if endpoint == "" {
		endpoint = defaultURL
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("deployment endpoint must be an absolute HTTP(S) URL without credentials or query")
	}
	return endpoint, nil
}

func request(ctx context.Context, httpClient *http.Client, method, endpoint string, headers map[string]string, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, nil, errors.New("invalid deployment request")
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		// Transport errors may contain URLs with API tokens in query strings.
		code := dnsgo.CodeResultUnknown
		if method == http.MethodGet || method == http.MethodHead {
			code = dnsgo.CodeTransport
		}
		return 0, nil, &dnsgo.Error{Provider: "deployment", Operation: method, Code: code,
			Message: "deployment request failed: " + sanitizedRequestError(err)}
	}
	defer resp.Body.Close()
	if (resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode >= 500) && method != http.MethodGet && method != http.MethodHead {
		return resp.StatusCode, nil, &dnsgo.Error{Provider: "deployment", Operation: method,
			Code: dnsgo.CodeResultUnknown, Message: fmt.Sprintf("deployment endpoint returned HTTP %d; read target state before retrying", resp.StatusCode)}
	}
	content, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		code := dnsgo.CodeResultUnknown
		if method == http.MethodGet || method == http.MethodHead {
			code = dnsgo.CodeTransport
		}
		return resp.StatusCode, nil, &dnsgo.Error{Provider: "deployment", Operation: method, Code: code,
			Message: "read deployment response failed"}
	}
	return resp.StatusCode, content, nil
}

func sanitizedRequestError(err error) string {
	if errors.Is(err, context.Canceled) {
		return "context canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	return "connection error"
}

func requestOutcomeError(provider, method, message string) error {
	code := dnsgo.CodeResultUnknown
	if method == http.MethodGet || method == http.MethodHead {
		code = dnsgo.CodeTransport
	}
	return &dnsgo.Error{Provider: provider, Operation: method, Code: code, Message: message}
}

func requestJSON(ctx context.Context, httpClient *http.Client, method, endpoint string, headers map[string]string, payload any) (int, []byte, error) {
	var body []byte
	if payload != nil {
		var err error
		body, err = json.Marshal(payload)
		if err != nil {
			return 0, nil, errors.New("encode deployment request failed")
		}
		headers = cloneHeaders(headers)
		headers["Content-Type"] = "application/json"
	}
	return request(ctx, httpClient, method, endpoint, headers, body)
}

func cloneHeaders(source map[string]string) map[string]string {
	copy := make(map[string]string, len(source)+1)
	for name, value := range source {
		copy[name] = value
	}
	return copy
}

func expectHTTPStatus(status int) error {
	if status >= 200 && status < 300 {
		return nil
	}
	return fmt.Errorf("deployment API returned HTTP %d", status)
}

func scalarID(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var value string
	if json.Unmarshal(raw, &value) == nil {
		return value
	}
	for _, char := range raw {
		if char < '0' || char > '9' {
			return ""
		}
	}
	return string(raw)
}
