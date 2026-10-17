package deploy

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

type DirectAdmin struct {
	endpoint string
	username string
	password string
	domains  []string
	client   *http.Client
}

var directAdminLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func init() {
	register("directadmin", func(config Config) (Target, error) {
		if config.Endpoint == "" {
			config.Endpoint = config.Values["url"]
		}
		endpoint, err := targetEndpoint(config, "")
		if err != nil {
			return nil, err
		}
		parsed, err := url.Parse(endpoint)
		if err != nil || parsed.Scheme != "https" || parsed.Path != "" && parsed.Path != "/" {
			return nil, errors.New("DirectAdmin endpoint must be an HTTPS origin without a path")
		}
		username, password := strings.TrimSpace(config.Values["username"]), config.Values["password"]
		if username == "" || password == "" {
			return nil, errors.New("DirectAdmin username and password are required")
		}
		var domains []string
		seen := map[string]bool{}
		for _, domain := range strings.FieldsFunc(config.Values["domain"], func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' }) {
			domain = strings.ToLower(strings.TrimSpace(domain))
			if !validDirectAdminDomain(domain) {
				return nil, errors.New("invalid DirectAdmin domain")
			}
			if !seen[domain] {
				domains = append(domains, domain)
				seen[domain] = true
			}
		}
		if len(domains) == 0 {
			return nil, errors.New("DirectAdmin deployment domains are required")
		}
		return &DirectAdmin{endpoint: endpoint, username: username, password: password, domains: domains, client: client(config)}, nil
	})
}

func validDirectAdminDomain(domain string) bool {
	if len(domain) < 1 || len(domain) > 253 {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if !directAdminLabel.MatchString(label) {
			return false
		}
	}
	return true
}

func (t *DirectAdmin) Kind() string { return "directadmin" }

func (t *DirectAdmin) Check(ctx context.Context) error {
	return t.call(ctx, http.MethodGet, "/CMD_API_LOGIN_TEST", nil)
}

func (t *DirectAdmin) Deploy(ctx context.Context, material Material) (Result, error) {
	pair, err := tls.X509KeyPair(material.FullChainPEM, material.PrivateKeyPEM)
	if err != nil {
		return Result{}, errors.New("certificate and private key are invalid or do not match")
	}
	privateKey, err := directAdminPrivateKey(pair, material.PrivateKeyPEM)
	if err != nil {
		return Result{}, err
	}
	combined := strings.TrimRight(string(privateKey), "\r\n") + "\n" + strings.TrimLeft(string(material.FullChainPEM), "\r\n")
	result := Result{Target: t.Kind()}
	for _, domain := range t.domains {
		values := url.Values{"domain": {domain}, "action": {"save"}, "type": {"paste"}, "certificate": {combined}}
		if err := t.call(ctx, http.MethodPost, "/CMD_API_SSL", values); err != nil {
			return result, err
		}
		result.Written = true
		if result.Location != "" {
			result.Location += ","
		}
		result.Location += domain
	}
	return result, nil
}

func directAdminPrivateKey(pair tls.Certificate, original []byte) ([]byte, error) {
	key, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return original, nil
	}
	block, _ := pem.Decode(original)
	if block == nil {
		return nil, errors.New("invalid DirectAdmin private key PEM")
	}
	if block.Type == "EC PRIVATE KEY" {
		return original, nil
	}
	if block.Type != "PRIVATE KEY" {
		return original, nil
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, errors.New("encode DirectAdmin EC private key failed")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

func (t *DirectAdmin) call(ctx context.Context, method, path string, values url.Values) error {
	headers := map[string]string{"Accept": "application/x-www-form-urlencoded, application/json",
		"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(t.username+":"+t.password))}
	var body []byte
	if values != nil {
		headers["Content-Type"] = "application/x-www-form-urlencoded"
		body = []byte(values.Encode())
	}
	status, content, err := request(ctx, t.client, method, t.endpoint+path, headers, body)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("DirectAdmin API returned HTTP %d", status)
	}
	trimmed := strings.TrimSpace(string(content))
	if trimmed == "" {
		return requestOutcomeError(t.Kind(), method, "DirectAdmin API returned an empty response")
	}
	var errorValue string
	if trimmed[0] == '{' || trimmed[0] == '[' {
		var result map[string]json.RawMessage
		if err := json.Unmarshal(content, &result); err != nil {
			return requestOutcomeError(t.Kind(), method, "invalid DirectAdmin JSON response")
		}
		raw, exists := result["error"]
		if !exists {
			return requestOutcomeError(t.Kind(), method, "DirectAdmin response lacks an error status")
		}
		errorValue = strings.Trim(string(raw), `" `)
	} else {
		result, err := url.ParseQuery(trimmed)
		if err != nil || !result.Has("error") {
			return requestOutcomeError(t.Kind(), method, "invalid DirectAdmin form response")
		}
		errorValue = result.Get("error")
	}
	if errorValue != "0" && errorValue != "false" {
		return errors.New("DirectAdmin API rejected certificate update")
	}
	return nil
}

var _ Target = (*DirectAdmin)(nil)
