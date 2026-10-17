package deploy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/rainchen537/dnsgo"
)

type Lucky struct {
	endpoint string
	token    string
	domains  map[string]bool
	client   *http.Client
}

func init() {
	register("lucky", func(config Config) (Target, error) {
		if config.Endpoint == "" {
			config.Endpoint = config.Values["url"]
		}
		config.Endpoint = strings.TrimRight(config.Endpoint, "/") + config.Values["path"]
		endpoint, err := targetEndpoint(config, "")
		if err != nil {
			return nil, err
		}
		token := strings.TrimSpace(config.Values["opentoken"])
		if token == "" {
			return nil, errors.New("Lucky OpenToken is required")
		}
		domains := make(map[string]bool)
		for _, domain := range splitList(config.Values["domainList"]) {
			domains[strings.ToLower(domain)] = true
		}
		if len(domains) == 0 {
			return nil, errors.New("Lucky deployment domain list is required")
		}
		return &Lucky{endpoint: endpoint, token: token, domains: domains, client: client(config)}, nil
	})
}

func (t *Lucky) Kind() string { return "lucky" }

func (t *Lucky) Check(ctx context.Context) error {
	_, err := t.call(ctx, http.MethodGet, "/api/modules/list", nil)
	return err
}

func (t *Lucky) Deploy(ctx context.Context, material Material) (Result, error) {
	if _, err := certificate(material); err != nil {
		return Result{}, err
	}
	data, err := t.call(ctx, http.MethodGet, "/api/ssl", nil)
	if err != nil {
		return Result{}, err
	}
	var list struct {
		List []struct {
			Key       json.RawMessage `json:"Key"`
			Remark    string          `json:"Remark"`
			CertsInfo struct {
				Domains []string `json:"Domains"`
			} `json:"CertsInfo"`
		} `json:"list"`
	}
	if err := json.Unmarshal(data, &list); err != nil {
		return Result{}, errors.New("invalid Lucky certificate list")
	}
	result := Result{Target: t.Kind()}
	failures := 0
	for _, row := range list.List {
		matched := false
		for _, domain := range row.CertsInfo.Domains {
			if t.domains[strings.ToLower(domain)] {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		payload := map[string]any{
			"Key": row.Key, "CertBase64": base64.StdEncoding.EncodeToString(material.FullChainPEM),
			"KeyBase64": base64.StdEncoding.EncodeToString(material.PrivateKeyPEM), "AddFrom": "file",
			"Enable": true, "MappingToPath": false, "Remark": row.Remark, "AllSyncClient": false,
		}
		if _, err := t.call(ctx, http.MethodPut, "/api/ssl", payload); err != nil {
			failures++
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
		result.Location += string(row.Key)
	}
	if !result.Written {
		return result, errors.New("Lucky matching certificates not found or every update failed")
	}
	if failures > 0 {
		return result, fmt.Errorf("Lucky failed to update %d matched certificates", failures)
	}
	return result, nil
}

func (t *Lucky) call(ctx context.Context, method, path string, payload any) ([]byte, error) {
	status, content, err := requestJSON(ctx, t.client, method, t.endpoint+path, map[string]string{"openToken": t.token}, payload)
	if err != nil {
		return nil, err
	}
	var response struct {
		Ret *int `json:"ret"`
	}
	if err := json.Unmarshal(content, &response); err != nil {
		return nil, requestOutcomeError(t.Kind(), method, "invalid Lucky API response")
	}
	if response.Ret == nil {
		return nil, requestOutcomeError(t.Kind(), method, "Lucky API returned no result code")
	}
	if status < 200 || status >= 300 || *response.Ret != 0 {
		return nil, fmt.Errorf("Lucky API rejected request (HTTP %d, ret %d)", status, *response.Ret)
	}
	return content, nil
}

func splitList(value string) []string {
	items := strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' })
	result := make([]string, 0, len(items))
	for _, item := range items {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}

var _ Target = (*Lucky)(nil)
