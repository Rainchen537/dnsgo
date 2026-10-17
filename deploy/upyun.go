package deploy

import (
	"context"
	"crypto/ecdsa"
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
)

type Upyun struct {
	endpoint string
	username string
	password string
	client   *http.Client
}

func init() {
	register("upyun", func(config Config) (Target, error) {
		endpoint, err := targetEndpoint(config, "https://console.upyun.com")
		if err != nil {
			return nil, err
		}
		username, password := strings.TrimSpace(config.Values["username"]), config.Values["password"]
		if username == "" || password == "" {
			return nil, errors.New("Upyun username and password are required")
		}
		return &Upyun{endpoint: endpoint, username: username, password: password, client: client(config)}, nil
	})
}

func (t *Upyun) Kind() string { return "upyun" }

func (t *Upyun) Check(ctx context.Context) error { _, err := t.login(ctx); return err }

func (t *Upyun) Deploy(ctx context.Context, material Material) (Result, error) {
	if _, err := certificate(material); err != nil {
		return Result{}, err
	}
	cookie, err := t.login(ctx)
	if err != nil {
		return Result{}, err
	}
	privateKey, err := upyunPrivateKey(material)
	if err != nil {
		return Result{}, err
	}
	data, err := t.call(ctx, http.MethodPost, "/api/https/certificate/", url.Values{
		"certificate": {string(material.FullChainPEM)}, "private_key": {string(privateKey)},
	}, cookie)
	if err != nil {
		return Result{Target: t.Kind(), Written: true}, err
	}
	var uploaded struct {
		CommonName    string          `json:"commonName"`
		CertificateID json.RawMessage `json:"certificate_id"`
	}
	if err := json.Unmarshal(data, &uploaded); err != nil {
		return Result{Target: t.Kind(), Written: true}, errors.New("Upyun certificate upload failed")
	}
	id := scalarID(uploaded.CertificateID)
	if id == "" {
		return Result{Target: t.Kind(), Written: true}, errors.New("Upyun uploaded certificate but did not return ID")
	}
	result := Result{Target: t.Kind(), Location: id, Written: true}
	query := url.Values{"limit": {"100"}, "domain": {uploaded.CommonName}}
	data, err = t.call(ctx, http.MethodGet, "/api/https/certificate/search?"+query.Encode(), nil, cookie)
	if err != nil {
		return result, err
	}
	var certificates map[string]struct {
		CommonName   string `json:"commonName"`
		ConfigDomain int    `json:"config_domain"`
	}
	if err := json.Unmarshal(data, &certificates); err != nil {
		return result, errors.New("invalid Upyun certificate search result")
	}
	for oldID, item := range certificates {
		if oldID == id || item.CommonName != uploaded.CommonName || item.ConfigDomain == 0 {
			continue
		}
		migrated, err := t.call(ctx, http.MethodPost, "/api/https/migrate/certificate", url.Values{
			"new_crt_id": {id}, "old_crt_id": {oldID},
		}, cookie)
		if err != nil {
			return result, err
		}
		var success bool
		if json.Unmarshal(migrated, &success) != nil || !success {
			return result, errors.New("Upyun certificate migration failed")
		}
	}
	return result, nil
}

func upyunPrivateKey(material Material) ([]byte, error) {
	pair, err := tls.X509KeyPair(material.FullChainPEM, material.PrivateKeyPEM)
	if err != nil {
		return nil, errors.New("invalid Upyun certificate material")
	}
	key, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return material.PrivateKeyPEM, nil
	}
	block, _ := pem.Decode(material.PrivateKeyPEM)
	if block != nil && block.Type == "EC PRIVATE KEY" {
		return material.PrivateKeyPEM, nil
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, errors.New("encode Upyun EC private key failed")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

func (t *Upyun) login(ctx context.Context) (string, error) {
	values := url.Values{"username": {t.username}, "password": {t.password}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.endpoint+"/accounts/signin/", strings.NewReader(values.Encode()))
	if err != nil {
		return "", errors.New("invalid Upyun login request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := t.client.Do(req)
	if err != nil {
		return "", errors.New("Upyun login request failed")
	}
	defer response.Body.Close()
	content, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		return "", errors.New("read Upyun login response failed")
	}
	var result struct {
		Data struct {
			Result bool `json:"result"`
		} `json:"data"`
	}
	if json.Unmarshal(content, &result) != nil || !result.Data.Result || response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("Upyun login failed (HTTP %d)", response.StatusCode)
	}
	var cookies []string
	for _, cookie := range response.Cookies() {
		if cookie.Name != "" && cookie.Value != "" && cookie.Value != "deleted" {
			cookies = append(cookies, cookie.Name+"="+cookie.Value)
		}
	}
	if len(cookies) == 0 {
		return "", errors.New("Upyun login did not return a session cookie")
	}
	return strings.Join(cookies, "; "), nil
}

func (t *Upyun) call(ctx context.Context, method, path string, values url.Values, cookie string) (json.RawMessage, error) {
	headers := map[string]string{"Cookie": cookie}
	var body []byte
	if values != nil {
		headers["Content-Type"] = "application/x-www-form-urlencoded"
		body = []byte(values.Encode())
	}
	status, content, err := request(ctx, t.client, method, t.endpoint+path, headers, body)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("Upyun API returned HTTP %d", status)
	}
	var response struct {
		Data struct {
			Result json.RawMessage `json:"result"`
			Status *int            `json:"status"`
		} `json:"data"`
	}
	if err := json.Unmarshal(content, &response); err != nil {
		return nil, requestOutcomeError(t.Kind(), method, "invalid Upyun API response")
	}
	if response.Data.Status != nil && *response.Data.Status != 0 {
		return nil, errors.New("Upyun API rejected request")
	}
	if len(response.Data.Result) == 0 {
		return nil, requestOutcomeError(t.Kind(), method, "Upyun API result is missing")
	}
	return response.Data.Result, nil
}

var _ Target = (*Upyun)(nil)
