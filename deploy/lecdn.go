package deploy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type LeCDN struct {
	endpoint string
	email    string
	password string
	apiKey   string
	id       string
	client   *http.Client
}

func init() {
	register("lecdn", func(config Config) (Target, error) {
		if config.Endpoint == "" {
			config.Endpoint = config.Values["url"]
		}
		endpoint, err := targetEndpoint(config, "")
		if err != nil {
			return nil, err
		}
		target := &LeCDN{endpoint: endpoint, id: strings.TrimSpace(config.Values["id"]), client: client(config)}
		if config.Values["auth"] == "1" {
			target.apiKey = strings.TrimSpace(config.Values["api_key"])
			if target.apiKey == "" {
				return nil, errors.New("LeCDN API key is required")
			}
		} else {
			target.email, target.password = strings.TrimSpace(config.Values["email"]), config.Values["password"]
			if target.email == "" || target.password == "" {
				return nil, errors.New("LeCDN email and password are required")
			}
		}
		return target, nil
	})
}

func (t *LeCDN) Kind() string { return "lecdn" }

func (t *LeCDN) Check(ctx context.Context) error {
	if t.apiKey == "" {
		_, err := t.login(ctx)
		return err
	}
	_, err := t.call(ctx, http.MethodGet, "/prod-api/system/info", nil, t.apiKey)
	return err
}

func (t *LeCDN) Deploy(ctx context.Context, material Material) (Result, error) {
	leaf, err := certificate(material)
	if err != nil {
		return Result{}, err
	}
	auth := t.apiKey
	if auth == "" {
		auth, err = t.login(ctx)
		if err != nil {
			return Result{}, err
		}
		auth = "Bearer " + auth
	}
	pem := base64.StdEncoding.EncodeToString(material.FullChainPEM)
	key := base64.StdEncoding.EncodeToString(material.PrivateKeyPEM)
	if t.id == "" {
		name := fmt.Sprintf("%s-%d", strings.TrimPrefix(leaf.Subject.CommonName, "*."), leaf.NotBefore.Unix())
		data, err := t.call(ctx, http.MethodPost, "/prod-api/certificate", map[string]any{
			"name": name, "type": "upload", "ssl_pem": pem, "ssl_key": key, "auto_renewal": false,
		}, auth)
		if err != nil {
			return Result{Target: t.Kind(), Written: true}, err
		}
		var created struct {
			ID json.Number `json:"id"`
		}
		if err := json.Unmarshal(data, &created); err != nil || created.ID == "" {
			return Result{Target: t.Kind(), Written: true}, errors.New("LeCDN created certificate but did not return ID")
		}
		return Result{Target: t.Kind(), Location: string(created.ID), Written: true}, nil
	}
	data, err := t.call(ctx, http.MethodGet, "/prod-api/certificate/"+url.PathEscape(t.id), nil, auth)
	if err != nil {
		return Result{}, err
	}
	var current struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(data, &current); err != nil {
		return Result{}, errors.New("invalid LeCDN certificate details")
	}
	id, err := strconv.ParseInt(t.id, 10, 64)
	if err != nil || id <= 0 {
		return Result{}, errors.New("LeCDN certificate ID must be numeric")
	}
	_, err = t.call(ctx, http.MethodPut, "/prod-api/certificate/"+url.PathEscape(t.id), map[string]any{
		"id": id, "name": current.Name, "description": current.Description,
		"type": "upload", "ssl_pem": pem, "ssl_key": key, "auto_renewal": false,
	}, auth)
	if err != nil {
		return Result{Target: t.Kind(), Location: t.id, Written: true}, err
	}
	return Result{Target: t.Kind(), Location: t.id, Written: true}, nil
}

func (t *LeCDN) login(ctx context.Context) (string, error) {
	data, err := t.call(ctx, http.MethodPost, "/prod-api/login", map[string]string{
		"email": t.email, "username": t.email, "password": t.password,
	}, "")
	if err != nil {
		return "", err
	}
	var session struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(data, &session); err != nil || session.Token == "" {
		return "", errors.New("LeCDN login did not return a token")
	}
	return session.Token, nil
}

func (t *LeCDN) call(ctx context.Context, method, path string, payload any, auth string) (json.RawMessage, error) {
	headers := map[string]string{}
	if auth != "" {
		headers["Authorization"] = auth
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
		if path == "/prod-api/login" {
			return nil, errors.New("invalid LeCDN login response")
		}
		return nil, requestOutcomeError(t.Kind(), method, "invalid LeCDN API response")
	}
	if status < 200 || status >= 300 || result.Code != 200 {
		return nil, fmt.Errorf("LeCDN API rejected request (HTTP %d, code %d)", status, result.Code)
	}
	return result.Data, nil
}

var _ Target = (*LeCDN)(nil)
