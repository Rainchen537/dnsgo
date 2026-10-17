package deploy

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rainchen537/dnsgo"
)

type BTWAF struct {
	endpoint string
	key      string
	panel    bool
	sites    []string
	client   *http.Client
}

func init() {
	register("btwaf", func(config Config) (Target, error) {
		if config.Endpoint == "" {
			config.Endpoint = config.Values["url"]
		}
		endpoint, err := targetEndpoint(config, "")
		if err != nil {
			return nil, err
		}
		key := strings.TrimSpace(config.Values["key"])
		if key == "" {
			return nil, errors.New("BTWAF API key is required")
		}
		panel := config.Values["type"] == "1"
		sites := splitList(config.Values["sites"])
		if !panel && len(sites) == 0 {
			return nil, errors.New("BTWAF site names are required")
		}
		return &BTWAF{endpoint: endpoint, key: key, panel: panel, sites: sites, client: client(config)}, nil
	})
}

func (t *BTWAF) Kind() string { return "btwaf" }

func (t *BTWAF) Check(ctx context.Context) error {
	_, err := t.call(ctx, "/api/user/latest_version", nil)
	return err
}

func (t *BTWAF) Deploy(ctx context.Context, material Material) (Result, error) {
	if _, err := certificate(material); err != nil {
		return Result{}, err
	}
	if t.panel {
		_, err := t.call(ctx, "/api/config/set_cert", map[string]string{"certContent": string(material.FullChainPEM), "keyContent": string(material.PrivateKeyPEM)})
		if err != nil {
			return Result{Target: t.Kind(), Location: "panel", Written: true}, err
		}
		return Result{Target: t.Kind(), Location: "panel", Written: true}, nil
	}
	result := Result{Target: t.Kind()}
	failures := 0
	for _, siteName := range t.sites {
		if err := t.deploySite(ctx, siteName, material); err != nil {
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
		result.Location += siteName
	}
	if !result.Written {
		return result, errors.New("BTWAF site deployment failed for every target")
	}
	if failures > 0 {
		return result, fmt.Errorf("BTWAF site deployment failed for %d targets", failures)
	}
	return result, nil
}

func (t *BTWAF) deploySite(ctx context.Context, name string, material Material) error {
	data, err := t.call(ctx, "/api/wafmastersite/get_site_list", map[string]any{"p": 1, "p_size": 10, "site_name": name})
	if err != nil {
		return err
	}
	var list struct {
		List []struct {
			SiteName string          `json:"site_name"`
			SiteID   json.RawMessage `json:"site_id"`
			Server   struct {
				ListenSSLPort json.RawMessage `json:"listen_ssl_port"`
			} `json:"server"`
		} `json:"list"`
	}
	if err := json.Unmarshal(data, &list); err != nil {
		return errors.New("invalid BTWAF site list")
	}
	for _, site := range list.List {
		if site.SiteName != name {
			continue
		}
		if scalarID(site.SiteID) == "" {
			return errors.New("BTWAF site ID is missing")
		}
		ports := site.Server.ListenSSLPort
		if len(ports) == 0 || string(ports) == "null" {
			ports = json.RawMessage(`["443"]`)
		}
		payload := map[string]any{"types": "openCert", "site_id": site.SiteID, "server": map[string]any{
			"listen_ssl_port": ports, "ssl": map[string]any{"is_ssl": 1, "private_key": string(material.PrivateKeyPEM), "full_chain": string(material.FullChainPEM)},
		}}
		_, err := t.call(ctx, "/api/wafmastersite/modify_site", payload)
		return err
	}
	return errors.New("BTWAF site was not found")
}

func (t *BTWAF) call(ctx context.Context, path string, payload any) (json.RawMessage, error) {
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	keyHash := md5.Sum([]byte(t.key))
	tokenHash := md5.Sum([]byte(timestamp + hex.EncodeToString(keyHash[:])))
	headers := map[string]string{"waf_request_time": timestamp, "waf_request_token": hex.EncodeToString(tokenHash[:]), "Content-Type": "application/json"}
	status, content, err := requestJSON(ctx, t.client, http.MethodPost, t.endpoint+path, headers, payload)
	if err != nil {
		return nil, err
	}
	var response struct {
		Code *int            `json:"code"`
		Res  json.RawMessage `json:"res"`
	}
	if err := json.Unmarshal(content, &response); err != nil {
		if path == "/api/config/set_cert" || path == "/api/wafmastersite/modify_site" {
			return nil, requestOutcomeError(t.Kind(), http.MethodPost, "invalid BTWAF certificate write response")
		}
		return nil, errors.New("invalid BTWAF API response")
	}
	if response.Code == nil {
		if path == "/api/config/set_cert" || path == "/api/wafmastersite/modify_site" {
			return nil, requestOutcomeError(t.Kind(), http.MethodPost, "BTWAF certificate write returned no result code")
		}
		return nil, errors.New("BTWAF API returned no result code")
	}
	if status < 200 || status >= 300 || *response.Code != 0 {
		return nil, fmt.Errorf("BTWAF API rejected request (HTTP %d, code %d)", status, *response.Code)
	}
	return response.Res, nil
}

var _ Target = (*BTWAF)(nil)
