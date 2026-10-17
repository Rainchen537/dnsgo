package deploy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
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

// AcePanel covers the identical upstream acepanel and ratpanel API protocols.
type AcePanel struct {
	kind     string
	endpoint string
	id       string
	token    string
	panel    bool
	sites    []string
	client   *http.Client
}

func init() {
	for _, name := range []string{"acepanel", "ratpanel"} {
		kind := name
		register(kind, func(config Config) (Target, error) {
			if config.Endpoint == "" {
				config.Endpoint = config.Values["url"]
			}
			endpoint, err := targetEndpoint(config, "")
			if err != nil {
				return nil, err
			}
			id, token := strings.TrimSpace(config.Values["id"]), strings.TrimSpace(config.Values["token"])
			if id == "" || token == "" {
				return nil, errors.New("AcePanel/RatPanel access ID and token are required")
			}
			panel := config.Values["type"] == "1"
			sites := splitList(config.Values["sites"])
			if !panel && len(sites) == 0 {
				return nil, errors.New("panel site names are required")
			}
			return &AcePanel{kind: kind, endpoint: endpoint, id: id, token: token, panel: panel, sites: sites, client: client(config)}, nil
		})
	}
}

func (t *AcePanel) Kind() string { return t.kind }

func (t *AcePanel) Check(ctx context.Context) error {
	return t.call(ctx, http.MethodGet, "/user/info", nil)
}

func (t *AcePanel) Deploy(ctx context.Context, material Material) (Result, error) {
	if _, err := certificate(material); err != nil {
		return Result{}, err
	}
	if t.panel {
		if err := t.call(ctx, http.MethodPost, "/setting/cert", map[string]string{"cert": string(material.FullChainPEM), "key": string(material.PrivateKeyPEM)}); err != nil {
			return Result{Target: t.Kind(), Location: "panel", Written: true}, err
		}
		return Result{Target: t.Kind(), Location: "panel", Written: true}, nil
	}
	result := Result{Target: t.Kind()}
	failures := 0
	for _, site := range t.sites {
		payload := map[string]string{"name": site, "cert": string(material.FullChainPEM), "key": string(material.PrivateKeyPEM)}
		if err := t.call(ctx, http.MethodPost, "/website/cert", payload); err != nil {
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
		return result, errors.New("panel certificate deployment failed for every target")
	}
	if failures > 0 {
		return result, fmt.Errorf("panel certificate deployment failed for %d sites", failures)
	}
	return result, nil
}

func (t *AcePanel) call(ctx context.Context, method, route string, payload any) error {
	path := "/api" + route
	var body []byte
	if payload != nil {
		var err error
		body, err = json.Marshal(payload)
		if err != nil {
			return errors.New("encode panel request failed")
		}
	}
	requestHash := sha256.Sum256(body)
	canonical := method + "\n" + path + "\n\n" + hex.EncodeToString(requestHash[:])
	canonicalHash := sha256.Sum256([]byte(canonical))
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	toSign := "HMAC-SHA256\n" + timestamp + "\n" + hex.EncodeToString(canonicalHash[:])
	mac := hmac.New(sha256.New, []byte(t.token))
	_, _ = mac.Write([]byte(toSign))
	headers := map[string]string{"Content-Type": "application/json", "X-Timestamp": timestamp,
		"Authorization": "HMAC-SHA256 Credential=" + t.id + ", Signature=" + hex.EncodeToString(mac.Sum(nil))}
	status, content, err := request(ctx, t.client, method, t.endpoint+path, headers, body)
	if err != nil {
		return err
	}
	var response struct {
		Msg string `json:"msg"`
	}
	if err := json.Unmarshal(content, &response); err != nil {
		return requestOutcomeError(t.Kind(), method, "invalid panel API response")
	}
	if response.Msg == "" && method != http.MethodGet {
		return requestOutcomeError(t.Kind(), method, "panel write response has no result")
	}
	if status < 200 || status >= 300 || response.Msg != "success" {
		return fmt.Errorf("panel API rejected request (HTTP %d)", status)
	}
	return nil
}

var _ Target = (*AcePanel)(nil)
