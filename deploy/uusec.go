package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

type UUSec struct {
	endpoint string
	username string
	password string
	id       int64
	name     string
	client   *http.Client
}

func init() {
	register("uusec", func(config Config) (Target, error) {
		if config.Endpoint == "" {
			config.Endpoint = config.Values["url"]
		}
		endpoint, err := targetEndpoint(config, "")
		if err != nil {
			return nil, err
		}
		username, password := strings.TrimSpace(config.Values["username"]), config.Values["password"]
		id, err := strconv.ParseInt(strings.TrimSpace(config.Values["id"]), 10, 64)
		if username == "" || password == "" || err != nil || id <= 0 {
			return nil, errors.New("UUSec username, password and numeric certificate ID are required")
		}
		return &UUSec{endpoint: endpoint, username: username, password: password, id: id, name: config.Values["name"], client: client(config)}, nil
	})
}

func (t *UUSec) Kind() string { return "uusec" }

func (t *UUSec) Check(ctx context.Context) error { _, err := t.login(ctx); return err }

func (t *UUSec) Deploy(ctx context.Context, material Material) (Result, error) {
	if _, err := certificate(material); err != nil {
		return Result{}, err
	}
	token, err := t.login(ctx)
	if err != nil {
		return Result{}, err
	}
	payload := map[string]any{"id": t.id, "type": 1, "name": t.name, "crt": string(material.FullChainPEM), "key": string(material.PrivateKeyPEM)}
	status, content, err := requestJSON(ctx, t.client, http.MethodPut, t.endpoint+"/api/v1/certs", map[string]string{"Authorization": "Bearer " + token}, payload)
	if err != nil {
		return Result{}, err
	}
	var response string
	if status != http.StatusOK || json.Unmarshal(content, &response) != nil || response != "OK" {
		return Result{Target: t.Kind(), Location: strconv.FormatInt(t.id, 10), Written: status >= 200 && status < 300},
			fmt.Errorf("UUSec certificate update failed (HTTP %d)", status)
	}
	return Result{Target: t.Kind(), Location: strconv.FormatInt(t.id, 10), Written: true}, nil
}

func (t *UUSec) login(ctx context.Context) (string, error) {
	status, content, err := requestJSON(ctx, t.client, http.MethodPost, t.endpoint+"/api/v1/users/login", nil,
		map[string]string{"usr": t.username, "pwd": t.password, "otp": ""})
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("UUSec login failed (HTTP %d)", status)
	}
	var response struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(content, &response); err != nil || response.Token == "" {
		return "", errors.New("UUSec login did not return a token")
	}
	return response.Token, nil
}

var _ Target = (*UUSec)(nil)
