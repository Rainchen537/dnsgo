package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/rainchen537/dnsgo"
)

type Safeline struct {
	endpoint string
	token    string
	domains  map[string]bool
	client   *http.Client
}

func init() {
	register("safeline", func(config Config) (Target, error) {
		if config.Endpoint == "" {
			config.Endpoint = config.Values["url"]
		}
		endpoint, err := targetEndpoint(config, "")
		if err != nil {
			return nil, err
		}
		token := strings.TrimSpace(config.Values["token"])
		if token == "" {
			return nil, errors.New("Safeline API token is required")
		}
		domains := make(map[string]bool)
		for _, domain := range strings.FieldsFunc(config.Values["domainList"], func(r rune) bool { return r == ',' || r == '\n' }) {
			if domain = strings.ToLower(strings.TrimSpace(domain)); domain != "" {
				domains[domain] = true
			}
		}
		if len(domains) == 0 {
			return nil, errors.New("Safeline deployment domain list is required")
		}
		return &Safeline{endpoint: endpoint, token: token, domains: domains, client: client(config)}, nil
	})
}

func (t *Safeline) Kind() string { return "safeline" }

func (t *Safeline) Check(ctx context.Context) error {
	_, err := t.call(ctx, "/api/open/system", nil)
	return err
}

func (t *Safeline) Deploy(ctx context.Context, material Material) (Result, error) {
	if _, err := certificate(material); err != nil {
		return Result{}, err
	}
	data, err := t.call(ctx, "/api/open/cert", nil)
	if err != nil {
		return Result{}, err
	}
	var list struct {
		Nodes []struct {
			ID      json.RawMessage `json:"id"`
			Domains []string        `json:"domains"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(data, &list); err != nil {
		return Result{}, errors.New("invalid Safeline certificate list")
	}
	result := Result{Target: t.Kind()}
	failures := 0
	matchedCount := 0
	for _, row := range list.Nodes {
		matched := false
		for _, domain := range row.Domains {
			if t.match(domain) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		matchedCount++
		payload := map[string]any{"id": row.ID, "manual": map[string]string{"crt": string(material.FullChainPEM), "key": string(material.PrivateKeyPEM)}, "type": 2}
		if _, err := t.call(ctx, "/api/open/cert", payload); err != nil {
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
		result.Location += string(row.ID)
	}
	if matchedCount == 0 {
		payload := map[string]any{"manual": map[string]string{"crt": string(material.FullChainPEM), "key": string(material.PrivateKeyPEM)}, "type": 2}
		if _, err := t.call(ctx, "/api/open/cert", payload); err != nil {
			result.Written = true
			return result, err
		}
		result.Written = true
		result.Location = "new certificate"
	}
	if failures > 0 {
		return result, fmt.Errorf("Safeline failed to update %d matched certificates", failures)
	}
	return result, nil
}

func (t *Safeline) match(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if t.domains[domain] {
		return true
	}
	if dot := strings.IndexByte(domain, '.'); dot >= 0 {
		return t.domains["*"+domain[dot:]]
	}
	return false
}

func (t *Safeline) call(ctx context.Context, path string, payload any) (json.RawMessage, error) {
	method := http.MethodGet
	if payload != nil {
		method = http.MethodPost
	}
	status, content, err := requestJSON(ctx, t.client, method, t.endpoint+path, map[string]string{"X-SLCE-API-TOKEN": t.token}, payload)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		if method == http.MethodPost && status >= 200 && status < 300 {
			return nil, requestOutcomeError(t.Kind(), method, "Safeline returned an unexpected success status")
		}
		return nil, fmt.Errorf("Safeline API returned HTTP %d", status)
	}
	var envelope map[string]json.RawMessage
	if json.Unmarshal(content, &envelope) != nil || len(envelope) == 0 {
		return nil, requestOutcomeError(t.Kind(), method, "invalid Safeline API response")
	}
	var result struct {
		Data json.RawMessage `json:"data"`
		Msg  string          `json:"msg"`
	}
	if err := json.Unmarshal(content, &result); err != nil {
		return nil, requestOutcomeError(t.Kind(), method, "invalid Safeline API response")
	}
	if result.Msg != "" && strings.Contains(strings.ToLower(result.Msg), "error") {
		return nil, errors.New("Safeline API rejected request")
	}
	return result.Data, nil
}

var _ Target = (*Safeline)(nil)
