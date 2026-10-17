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

type CDNFly struct {
	endpoint  string
	apiKey    string
	apiSecret string
	username  string
	password  string
	id        string
	client    *http.Client
}

func init() {
	register("cdnfly", func(config Config) (Target, error) {
		if config.Endpoint == "" {
			config.Endpoint = config.Values["url"]
		}
		endpoint, err := targetEndpoint(config, "")
		if err != nil {
			return nil, err
		}
		target := &CDNFly{endpoint: endpoint, id: strings.TrimSpace(config.Values["id"]), client: client(config)}
		if config.Values["auth"] == "1" {
			target.username, target.password = strings.TrimSpace(config.Values["username"]), config.Values["password"]
			if target.username == "" || target.password == "" {
				return nil, errors.New("CDNFly username and password are required")
			}
		} else {
			target.apiKey, target.apiSecret = strings.TrimSpace(config.Values["api_key"]), strings.TrimSpace(config.Values["api_secret"])
			if target.apiKey == "" || target.apiSecret == "" {
				return nil, errors.New("CDNFly API key and secret are required")
			}
		}
		return target, nil
	})
}

func (t *CDNFly) Kind() string { return "cdnfly" }

func (t *CDNFly) Check(ctx context.Context) error {
	if t.username != "" {
		_, err := t.login(ctx)
		return err
	}
	_, err := t.call(ctx, http.MethodGet, "/v1/user", nil, "")
	return err
}

func (t *CDNFly) Deploy(ctx context.Context, material Material) (Result, error) {
	leaf, err := certificate(material)
	if err != nil {
		return Result{}, err
	}
	token := ""
	if t.username != "" {
		token, err = t.login(ctx)
		if err != nil {
			return Result{}, err
		}
	}
	payload := map[string]string{"type": "custom", "cert": string(material.FullChainPEM), "key": string(material.PrivateKeyPEM)}
	method, path := http.MethodPut, "/v1/certs/"+url.PathEscape(t.id)
	if t.id == "" {
		method, path = http.MethodPost, "/v1/certs"
		payload["name"] = fmt.Sprintf("%s-%d", strings.TrimPrefix(leaf.Subject.CommonName, "*."), leaf.NotBefore.Unix())
	}
	data, err := t.call(ctx, method, path, payload, token)
	if err != nil {
		return Result{Target: t.Kind(), Location: t.id, Written: true}, err
	}
	id := t.id
	if id == "" {
		id = scalarID(data)
		if id == "" {
			var object struct {
				ID json.RawMessage `json:"id"`
			}
			_ = json.Unmarshal(data, &object)
			id = scalarID(object.ID)
		}
		if id == "" {
			return Result{Target: t.Kind(), Written: true}, errors.New("CDNFly created certificate but did not return ID")
		}
	}
	return Result{Target: t.Kind(), Location: id, Written: true}, nil
}

func (t *CDNFly) login(ctx context.Context) (string, error) {
	status, content, err := requestJSON(ctx, t.client, http.MethodPost, t.endpoint+"/v1/login", nil,
		map[string]string{"account": t.username, "password": t.password})
	if err != nil {
		return "", err
	}
	var result struct {
		Code int `json:"code"`
		Data struct {
			AccessToken string `json:"access_token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(content, &result); err != nil {
		return "", errors.New("invalid CDNFly login response")
	}
	if status < 200 || status >= 300 || result.Code != 0 || result.Data.AccessToken == "" {
		return "", fmt.Errorf("CDNFly login failed (HTTP %d, code %d)", status, result.Code)
	}
	return result.Data.AccessToken, nil
}

func (t *CDNFly) call(ctx context.Context, method, path string, payload any, token string) (json.RawMessage, error) {
	headers := map[string]string{}
	if token != "" {
		headers["Access-Token"] = token
	} else {
		headers["api-key"], headers["api-secret"] = t.apiKey, t.apiSecret
	}
	status, content, err := requestJSON(ctx, t.client, method, t.endpoint+path, headers, payload)
	if err != nil {
		return nil, err
	}
	var result struct {
		Code int             `json:"code"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(content, &result); err != nil {
		return nil, errors.New("invalid CDNFly API response")
	}
	if status < 200 || status >= 300 || result.Code != 0 {
		return nil, fmt.Errorf("CDNFly API rejected request (HTTP %d, code %d)", status, result.Code)
	}
	return result.Data, nil
}

var _ Target = (*CDNFly)(nil)
