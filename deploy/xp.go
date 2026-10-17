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

type XP struct {
	endpoint string
	apiKey   string
	sites    map[string]bool
	client   *http.Client
}

func init() {
	register("xp", func(config Config) (Target, error) {
		if config.Endpoint == "" {
			config.Endpoint = config.Values["url"]
		}
		endpoint, err := targetEndpoint(config, "")
		if err != nil {
			return nil, err
		}
		key := strings.TrimSpace(config.Values["apikey"])
		if key == "" {
			return nil, errors.New("XP panel API key is required")
		}
		sites := make(map[string]bool)
		for _, site := range strings.Split(config.Values["sites"], "\n") {
			if site = strings.TrimSpace(site); site != "" {
				sites[site] = true
			}
		}
		if len(sites) == 0 {
			return nil, errors.New("XP panel site list is required")
		}
		return &XP{endpoint: endpoint, apiKey: key, sites: sites, client: client(config)}, nil
	})
}

func (t *XP) Kind() string { return "xp" }

func (t *XP) Check(ctx context.Context) error { _, err := t.list(ctx); return err }

func (t *XP) Deploy(ctx context.Context, material Material) (Result, error) {
	if _, err := certificate(material); err != nil {
		return Result{}, err
	}
	sites, err := t.list(ctx)
	if err != nil {
		return Result{}, err
	}
	result := Result{Target: t.Kind()}
	failures := 0
	for _, site := range sites {
		if !t.sites[site.Name] {
			continue
		}
		if err := t.call(ctx, "/openApi/setSSL", map[string]any{"id": site.ID, "key": string(material.PrivateKeyPEM), "pem": string(material.FullChainPEM)}, nil); err != nil {
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
		result.Location += site.Name
	}
	if !result.Written {
		return result, errors.New("XP panel sites not found or every deployment failed")
	}
	if failures > 0 {
		return result, fmt.Errorf("XP panel deployment failed for %d selected sites", failures)
	}
	return result, nil
}

type xpSite struct {
	ID   json.RawMessage `json:"id"`
	Name string          `json:"name"`
}

func (t *XP) list(ctx context.Context) ([]xpSite, error) {
	var sites []xpSite
	if err := t.call(ctx, "/openApi/siteList", nil, &sites); err != nil {
		return nil, err
	}
	return sites, nil
}

func (t *XP) call(ctx context.Context, path string, payload any, destination any) error {
	method := http.MethodGet
	if payload != nil {
		method = http.MethodPost
	}
	status, content, err := requestJSON(ctx, t.client, method, t.endpoint+path, map[string]string{"XP-API-KEY": t.apiKey}, payload)
	if err != nil {
		return err
	}
	var result struct {
		Code int             `json:"code"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(content, &result); err != nil {
		return requestOutcomeError(t.Kind(), method, "invalid XP panel API response")
	}
	if status < 200 || status >= 300 || result.Code != 1000 {
		return fmt.Errorf("XP panel API rejected request (HTTP %d, code %d)", status, result.Code)
	}
	if destination != nil && json.Unmarshal(result.Data, destination) != nil {
		return errors.New("invalid XP panel data")
	}
	return nil
}

var _ Target = (*XP)(nil)
