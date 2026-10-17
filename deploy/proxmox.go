package deploy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type Proxmox struct {
	endpoint string
	apiUser  string
	apiKey   string
	node     string
	client   *http.Client
}

func init() {
	register("proxmox", func(config Config) (Target, error) {
		if config.Endpoint == "" {
			config.Endpoint = config.Values["url"]
		}
		endpoint, err := targetEndpoint(config, "")
		if err != nil {
			return nil, err
		}
		apiUser, apiKey, node := strings.TrimSpace(config.Values["api_user"]), strings.TrimSpace(config.Values["api_key"]), strings.TrimSpace(config.Values["node"])
		if apiUser == "" || apiKey == "" || node == "" {
			return nil, errors.New("Proxmox API user, key and node are required")
		}
		return &Proxmox{endpoint: endpoint, apiUser: apiUser, apiKey: apiKey, node: node, client: client(config)}, nil
	})
}

func (t *Proxmox) Kind() string { return "proxmox" }

func (t *Proxmox) Check(ctx context.Context) error {
	_, err := t.call(ctx, http.MethodGet, "/api2/json/access", nil)
	return err
}

func (t *Proxmox) Deploy(ctx context.Context, material Material) (Result, error) {
	leaf, err := certificate(material)
	if err != nil {
		return Result{}, err
	}
	hash := sha256.Sum256(leaf.Raw)
	fingerprint := hex.EncodeToString(hash[:])
	path := "/api2/json/nodes/" + url.PathEscape(t.node) + "/certificates"
	response, err := t.call(ctx, http.MethodGet, path+"/info", nil)
	if err != nil {
		return Result{}, err
	}
	var installed []struct {
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.Unmarshal(response, &installed); err != nil {
		return Result{}, errors.New("invalid Proxmox certificate list")
	}
	for _, item := range installed {
		if strings.EqualFold(strings.ReplaceAll(item.Fingerprint, ":", ""), fingerprint) {
			return Result{Target: t.Kind(), Location: t.node, Written: false}, nil
		}
	}
	values := url.Values{"certificates": {string(material.FullChainPEM)}, "key": {string(material.PrivateKeyPEM)}, "force": {"1"}, "restart": {"1"}}
	if _, err := t.call(ctx, http.MethodPost, path+"/custom", values); err != nil {
		return Result{Target: t.Kind(), Location: t.node, Written: true}, err
	}
	return Result{Target: t.Kind(), Location: t.node, Written: true}, nil
}

func (t *Proxmox) call(ctx context.Context, method, path string, values url.Values) (json.RawMessage, error) {
	headers := map[string]string{"Authorization": "PVEAPIToken=" + t.apiUser + "=" + t.apiKey}
	var body []byte
	if values != nil {
		headers["Content-Type"] = "application/x-www-form-urlencoded"
		body = []byte(values.Encode())
	}
	status, content, err := request(ctx, t.client, method, t.endpoint+path, headers, body)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("Proxmox API returned HTTP %d", status)
	}
	var result struct {
		Data   json.RawMessage `json:"data"`
		Errors json.RawMessage `json:"errors"`
	}
	if err := json.Unmarshal(content, &result); err != nil || len(result.Data) == 0 || string(result.Data) == "null" {
		return nil, requestOutcomeError(t.Kind(), method, "invalid Proxmox API response")
	}
	return result.Data, nil
}

var _ Target = (*Proxmox)(nil)
