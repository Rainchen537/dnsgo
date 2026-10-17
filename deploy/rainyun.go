package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type Rainyun struct {
	endpoint string
	apiKey   string
	id       string
	client   *http.Client
}

func init() {
	register("rainyun", func(config Config) (Target, error) {
		endpoint, err := targetEndpoint(config, "https://api.v2.rainyun.com")
		if err != nil {
			return nil, err
		}
		key := strings.TrimSpace(config.Values["apikey"])
		if key == "" {
			return nil, errors.New("Rainyun API key is required")
		}
		return &Rainyun{endpoint: endpoint, apiKey: key, id: strings.TrimSpace(config.Values["id"]), client: client(config)}, nil
	})
}

func (t *Rainyun) Kind() string { return "rainyun" }

func (t *Rainyun) Check(ctx context.Context) error {
	_, err := t.call(ctx, http.MethodGet, "/product/", nil)
	return err
}

func (t *Rainyun) Deploy(ctx context.Context, material Material) (Result, error) {
	if _, err := certificate(material); err != nil {
		return Result{}, err
	}
	payload := map[string]string{"cert": string(material.FullChainPEM), "key": string(material.PrivateKeyPEM)}
	if t.id != "" {
		if _, err := t.call(ctx, http.MethodPut, "/product/sslcenter/"+url.PathEscape(t.id), payload); err != nil {
			return Result{Target: t.Kind(), Location: t.id, Written: true}, err
		}
		return Result{Target: t.Kind(), Location: t.id, Written: true}, nil
	}
	before, err := t.certificateIDs(ctx)
	if err != nil {
		return Result{}, err
	}
	data, err := t.call(ctx, http.MethodPost, "/product/sslcenter/", payload)
	if err != nil {
		return Result{Target: t.Kind(), Written: true}, err
	}
	var created struct {
		ID json.Number `json:"ID"`
	}
	_ = json.Unmarshal(data, &created)
	if created.ID != "" {
		return Result{Target: t.Kind(), Location: string(created.ID), Written: true}, nil
	}
	after, err := t.certificateIDs(ctx)
	if err != nil {
		return Result{Target: t.Kind(), Written: true}, fmt.Errorf("certificate uploaded, but ID lookup failed: %w", err)
	}
	var createdIDs []string
	for id := range after {
		if !before[id] {
			createdIDs = append(createdIDs, id)
		}
	}
	if len(createdIDs) != 1 {
		return Result{Target: t.Kind(), Written: true}, errors.New("certificate uploaded, but its ID is ambiguous; inspect Rainyun before retrying")
	}
	return Result{Target: t.Kind(), Location: createdIDs[0], Written: true}, nil
}

func (t *Rainyun) certificateIDs(ctx context.Context) (map[string]bool, error) {
	ids := map[string]bool{}
	for page := 1; page <= 100; page++ {
		options, _ := json.Marshal(map[string]any{"columnFilters": map[string]string{"Domain": ""},
			"sort": []any{}, "page": page, "perPage": 100})
		query := url.Values{"options": {string(options)}}
		data, err := t.call(ctx, http.MethodGet, "/product/sslcenter/?"+query.Encode(), nil)
		if err != nil {
			return nil, err
		}
		var list struct {
			Records []struct {
				ID json.Number `json:"ID"`
			} `json:"Records"`
		}
		if err := json.Unmarshal(data, &list); err != nil {
			return nil, errors.New("invalid Rainyun certificate list")
		}
		if len(list.Records) == 0 {
			return ids, nil
		}
		added := 0
		for _, item := range list.Records {
			if item.ID != "" && !ids[string(item.ID)] {
				ids[string(item.ID)] = true
				added++
			}
		}
		if added == 0 {
			return ids, nil
		}
	}
	return nil, errors.New("Rainyun certificate list exceeded 100 pages")
}

func (t *Rainyun) call(ctx context.Context, method, path string, payload any) (json.RawMessage, error) {
	status, content, err := requestJSON(ctx, t.client, method, t.endpoint+path, map[string]string{"x-api-key": t.apiKey}, payload)
	if err != nil {
		return nil, err
	}
	var result struct {
		Code int             `json:"code"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(content, &result); err != nil {
		return nil, requestOutcomeError(t.Kind(), method, "invalid Rainyun API response")
	}
	if status < 200 || status >= 300 || result.Code != 200 {
		return nil, fmt.Errorf("Rainyun API rejected request (HTTP %d, code %d)", status, result.Code)
	}
	return result.Data, nil
}

var _ Target = (*Rainyun)(nil)
