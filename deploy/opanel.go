package deploy

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rainchen537/dnsgo"
)

type OPanel struct {
	endpoint string
	key      string
	panel    bool
	id       string
	domains  map[string]bool
	nodes    []string
	client   *http.Client
}

func init() {
	register("opanel", func(config Config) (Target, error) {
		if config.Endpoint == "" {
			config.Endpoint = config.Values["url"]
		}
		version := strings.Trim(config.Values["version"], "/")
		if version == "" {
			version = "v1"
		}
		config.Endpoint = strings.TrimRight(config.Endpoint, "/") + "/api/" + version
		endpoint, err := targetEndpoint(config, "")
		if err != nil {
			return nil, err
		}
		key := strings.TrimSpace(config.Values["key"])
		if key == "" {
			return nil, errors.New("1Panel API key is required")
		}
		panel := config.Values["type"] == "3"
		id := strings.TrimSpace(config.Values["id"])
		domains := make(map[string]bool)
		for _, domain := range splitList(config.Values["domainList"]) {
			domains[strings.ToLower(domain)] = true
		}
		if !panel && id == "" && len(domains) == 0 {
			return nil, errors.New("1Panel certificate ID or domain list is required")
		}
		return &OPanel{endpoint: endpoint, key: key, panel: panel, id: id, domains: domains,
			nodes: splitList(config.Values["node_name"]), client: client(config)}, nil
	})
}

func (t *OPanel) Kind() string { return "opanel" }

func (t *OPanel) Check(ctx context.Context) error {
	_, err := t.call(ctx, "/settings/search", nil, "")
	return err
}

func (t *OPanel) Deploy(ctx context.Context, material Material) (Result, error) {
	if _, err := certificate(material); err != nil {
		return Result{}, err
	}
	nodes := append([]string{""}, t.nodes...)
	result := Result{Target: t.Kind()}
	failures := 0
	for _, node := range nodes {
		location, err := t.deployNode(ctx, node, material)
		if err != nil {
			failures++
			if location != "" {
				result.Written = true
				if result.Location != "" {
					result.Location += ","
				}
				result.Location += location
			}
			if dnsgo.IsCode(err, dnsgo.CodeResultUnknown) {
				result.Written = true
				return result, err
			}
			continue
		}
		result.Written = true
		if result.Location != "" {
			result.Location += ","
		}
		if node == "" {
			result.Location += "main:"
		} else {
			result.Location += node + ":"
		}
		result.Location += location
	}
	if !result.Written {
		return result, errors.New("1Panel certificate deployment failed for every node")
	}
	if failures > 0 {
		return result, fmt.Errorf("1Panel certificate deployment failed for %d nodes", failures)
	}
	return result, nil
}

func (t *OPanel) deployNode(ctx context.Context, node string, material Material) (string, error) {
	if t.panel {
		_, err := t.call(ctx, "/core/settings/ssl/update", map[string]any{
			"cert": string(material.FullChainPEM), "key": string(material.PrivateKeyPEM), "ssl": "Enable", "sslID": nil, "sslType": "import-paste",
		}, node)
		return "panel", err
	}
	if t.id != "" {
		id, err := strconv.ParseInt(t.id, 10, 64)
		if err != nil || id <= 0 {
			return "", errors.New("1Panel certificate ID must be numeric")
		}
		return t.upload(ctx, node, id, material)
	}
	data, err := t.call(ctx, "/websites/ssl/search", map[string]any{
		"page": 1, "pageSize": 500, "orderBy": "expire_date", "order": "null",
	}, node)
	if err != nil {
		return "", err
	}
	var list struct {
		Items []struct {
			ID            int64  `json:"id"`
			PrimaryDomain string `json:"primaryDomain"`
			Domains       string `json:"domains"`
		} `json:"items"`
	}
	if err := json.Unmarshal(data, &list); err != nil {
		return "", errors.New("invalid 1Panel certificate list")
	}
	var updated []string
	matched, failed := 0, 0
	for _, item := range list.Items {
		if item.ID <= 0 || !t.matches(item.PrimaryDomain) && !t.matchesAny(splitList(item.Domains)) {
			continue
		}
		matched++
		if _, err := t.upload(ctx, node, item.ID, material); err != nil {
			if dnsgo.IsCode(err, dnsgo.CodeResultUnknown) {
				return strings.Join(updated, "+"), err
			}
			failed++
			continue
		}
		updated = append(updated, strconv.FormatInt(item.ID, 10))
	}
	if matched > 0 {
		if failed > 0 {
			return strings.Join(updated, "+"), fmt.Errorf("1Panel certificate update failed for %d matched targets", failed)
		}
		return strings.Join(updated, "+"), nil
	}
	return t.upload(ctx, node, 0, material)
}

func (t *OPanel) matchesAny(domains []string) bool {
	for _, domain := range domains {
		if t.matches(domain) {
			return true
		}
	}
	return false
}

func (t *OPanel) matches(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if t.domains[domain] {
		return true
	}
	if dot := strings.IndexByte(domain, '.'); dot >= 0 {
		return t.domains["*"+domain[dot:]]
	}
	return false
}

func (t *OPanel) upload(ctx context.Context, node string, id int64, material Material) (string, error) {
	_, err := t.call(ctx, "/websites/ssl/upload", map[string]any{
		"sslID": id, "type": "paste", "certificate": string(material.FullChainPEM),
		"privateKey": string(material.PrivateKeyPEM), "description": "",
	}, node)
	if err != nil {
		return "", err
	}
	if id == 0 {
		return "new", nil
	}
	return strconv.FormatInt(id, 10), nil
}

func (t *OPanel) call(ctx context.Context, path string, payload any, node string) (json.RawMessage, error) {
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	hash := md5.Sum([]byte("1panel" + t.key + timestamp))
	headers := map[string]string{"1Panel-Token": hex.EncodeToString(hash[:]), "1Panel-Timestamp": timestamp, "Content-Type": "application/json"}
	if node != "" {
		headers["CurrentNode"] = node
	}
	if payload == nil {
		payload = struct{}{}
	}
	status, content, err := requestJSON(ctx, t.client, http.MethodPost, t.endpoint+path, headers, payload)
	if err != nil {
		return nil, err
	}
	var response struct {
		Code int             `json:"code"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(content, &response); err != nil {
		if path == "/core/settings/ssl/update" || path == "/websites/ssl/upload" {
			return nil, requestOutcomeError(t.Kind(), http.MethodPost, "invalid 1Panel certificate write response")
		}
		return nil, errors.New("invalid 1Panel API response")
	}
	if status < 200 || status >= 300 || response.Code != 200 {
		return nil, fmt.Errorf("1Panel API rejected request (HTTP %d, code %d)", status, response.Code)
	}
	return response.Data, nil
}

var _ Target = (*OPanel)(nil)
