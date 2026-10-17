package deploy

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Doge struct {
	endpoint       string
	accessKey      string
	secretKey      string
	domains        []string
	cleanupExpired bool
	client         *http.Client
}

func init() {
	register("doge", func(config Config) (Target, error) {
		endpoint, err := targetEndpoint(config, "https://api.dogecloud.com")
		if err != nil {
			return nil, err
		}
		accessKey, secretKey := strings.TrimSpace(config.Values["AccessKey"]), config.Values["SecretKey"]
		domains := splitList(config.Values["domain"])
		if accessKey == "" || secretKey == "" || len(domains) == 0 {
			return nil, errors.New("DogeCloud access key, secret key and domains are required")
		}
		return &Doge{endpoint: endpoint, accessKey: accessKey, secretKey: secretKey, domains: domains,
			cleanupExpired: config.Values["cleanup_expired"] == "true", client: client(config)}, nil
	})
}

func (t *Doge) Kind() string { return "doge" }

func (t *Doge) Check(ctx context.Context) error {
	_, err := t.call(ctx, "/cdn/cert/list.json", nil)
	return err
}

func (t *Doge) Deploy(ctx context.Context, material Material) (Result, error) {
	leaf, err := certificate(material)
	if err != nil {
		return Result{}, err
	}
	name := fmt.Sprintf("%s-%d", strings.TrimPrefix(leaf.Subject.CommonName, "*."), leaf.NotBefore.Unix())
	data, err := t.call(ctx, "/cdn/cert/list.json", nil)
	if err != nil {
		return Result{}, err
	}
	var list struct {
		Certs []struct {
			ID          json.RawMessage `json:"id"`
			Note        string          `json:"note"`
			Expire      int64           `json:"expire"`
			DomainCount int             `json:"domainCount"`
		} `json:"certs"`
	}
	if err := json.Unmarshal(data, &list); err != nil {
		return Result{}, errors.New("invalid DogeCloud certificate list")
	}
	var id string
	for _, item := range list.Certs {
		if item.Note == name {
			id = scalarID(item.ID)
		}
		if t.cleanupExpired && item.Expire > 0 && item.Expire < time.Now().Unix() && item.DomainCount == 0 && item.Note != name {
			if expiredID := scalarID(item.ID); expiredID != "" {
				_, _ = t.call(ctx, "/cdn/cert/delete.json", url.Values{"id": {expiredID}})
			}
		}
	}
	uploadedNew := false
	if id == "" {
		data, err = t.call(ctx, "/cdn/cert/upload.json", url.Values{
			"note": {name}, "cert": {string(material.FullChainPEM)}, "private": {string(material.PrivateKeyPEM)},
		})
		if err != nil {
			return Result{Target: t.Kind(), Written: true}, err
		}
		var uploaded struct {
			ID json.RawMessage `json:"id"`
		}
		if json.Unmarshal(data, &uploaded) != nil || scalarID(uploaded.ID) == "" {
			return Result{Target: t.Kind(), Written: true}, errors.New("DogeCloud uploaded certificate but did not return ID")
		}
		id = scalarID(uploaded.ID)
		uploadedNew = true
		if err := waitContext(ctx, 500*time.Millisecond); err != nil {
			return Result{Target: t.Kind(), Location: id, Written: true}, err
		}
	}
	result := Result{Target: t.Kind(), Location: id, Written: uploadedNew}
	for _, domain := range t.domains {
		if _, err := t.call(ctx, "/cdn/cert/bind.json", url.Values{"id": {id}, "domain": {domain}}); err != nil {
			result.Written = true
			return result, err
		}
		result.Written = true
	}
	return result, nil
}

func (t *Doge) call(ctx context.Context, path string, values url.Values) (json.RawMessage, error) {
	method := http.MethodGet
	var body []byte
	headers := map[string]string{}
	if values != nil {
		method = http.MethodPost
		body = []byte(values.Encode())
		headers["Content-Type"] = "application/x-www-form-urlencoded"
	}
	mac := hmac.New(sha1.New, []byte(t.secretKey))
	_, _ = mac.Write([]byte(path + "\n" + string(body)))
	headers["Authorization"] = "TOKEN " + t.accessKey + ":" + hex.EncodeToString(mac.Sum(nil))
	status, content, err := request(ctx, t.client, method, t.endpoint+path, headers, body)
	if err != nil {
		return nil, err
	}
	var result struct {
		Code int             `json:"code"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(content, &result); err != nil {
		return nil, requestOutcomeError(t.Kind(), method, "invalid DogeCloud API response")
	}
	if status < 200 || status >= 300 || result.Code != 200 {
		return nil, fmt.Errorf("DogeCloud API rejected request (HTTP %d, code %d)", status, result.Code)
	}
	return result.Data, nil
}

func waitContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

var _ Target = (*Doge)(nil)
