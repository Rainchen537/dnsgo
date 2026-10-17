package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/rainchen537/dnsgo"
)

type MWPanel struct {
	endpoint  string
	appID     string
	appSecret string
	panel     bool
	sites     []string
	client    *http.Client
}

func init() {
	register("mwpanel", func(config Config) (Target, error) {
		if config.Endpoint == "" {
			config.Endpoint = config.Values["url"]
		}
		endpoint, err := targetEndpoint(config, "")
		if err != nil {
			return nil, err
		}
		appID, appSecret := strings.TrimSpace(config.Values["appid"]), config.Values["appsecret"]
		if appID == "" || appSecret == "" {
			return nil, errors.New("MWPanel app ID and secret are required")
		}
		panel := config.Values["type"] == "1"
		sites := splitList(config.Values["sites"])
		if !panel && len(sites) == 0 {
			return nil, errors.New("MWPanel site names are required")
		}
		return &MWPanel{endpoint: endpoint, appID: appID, appSecret: appSecret, panel: panel, sites: sites, client: client(config)}, nil
	})
}

func (t *MWPanel) Kind() string { return "mwpanel" }

func (t *MWPanel) Check(ctx context.Context) error { return t.call(ctx, "/task/count", nil) }

func (t *MWPanel) Deploy(ctx context.Context, material Material) (Result, error) {
	if _, err := certificate(material); err != nil {
		return Result{}, err
	}
	if t.panel {
		values := url.Values{"privateKey": {string(material.PrivateKeyPEM)}, "certPem": {string(material.FullChainPEM)}, "choose": {"local"}}
		if err := t.call(ctx, "/setting/save_panel_ssl", values); err != nil {
			return Result{Target: t.Kind(), Location: "panel", Written: true}, err
		}
		return Result{Target: t.Kind(), Location: "panel", Written: true}, nil
	}
	result := Result{Target: t.Kind()}
	failures := 0
	for _, site := range t.sites {
		values := url.Values{"type": {"1"}, "siteName": {site}, "key": {string(material.PrivateKeyPEM)}, "csr": {string(material.FullChainPEM)}}
		if err := t.call(ctx, "/site/set_ssl", values); err != nil {
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
		result.Location += site
	}
	if !result.Written {
		return result, errors.New("MWPanel site deployment failed for every target")
	}
	if failures > 0 {
		return result, fmt.Errorf("MWPanel site deployment failed for %d targets", failures)
	}
	return result, nil
}

func (t *MWPanel) call(ctx context.Context, path string, values url.Values) error {
	method := http.MethodGet
	headers := map[string]string{"app-id": t.appID, "app-secret": t.appSecret}
	var body []byte
	if values != nil {
		method = http.MethodPost
		headers["Content-Type"] = "application/x-www-form-urlencoded"
		body = []byte(values.Encode())
	}
	status, content, err := request(ctx, t.client, method, t.endpoint+path, headers, body)
	if err != nil {
		return err
	}
	var response struct {
		Status json.RawMessage `json:"status"`
	}
	if err := json.Unmarshal(content, &response); err != nil {
		return requestOutcomeError(t.Kind(), method, "invalid MWPanel API response")
	}
	if len(response.Status) == 0 {
		return requestOutcomeError(t.Kind(), method, "MWPanel API returned no status")
	}
	if status < 200 || status >= 300 || !jsonTruthy(response.Status) {
		return fmt.Errorf("MWPanel API rejected request (HTTP %d)", status)
	}
	return nil
}

var _ Target = (*MWPanel)(nil)
