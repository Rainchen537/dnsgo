package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Kuocai struct {
	endpoint string
	username string
	password string
	id       string
	client   *http.Client
}

func init() {
	register("kuocai", func(config Config) (Target, error) {
		endpoint, err := targetEndpoint(config, "https://www.kuocaicdn.com")
		if err != nil {
			return nil, err
		}
		username, password, id := strings.TrimSpace(config.Values["username"]), config.Values["password"], strings.TrimSpace(config.Values["id"])
		if username == "" || password == "" || id == "" {
			return nil, errors.New("Kuocai username, password and domain ID are required")
		}
		return &Kuocai{endpoint: endpoint, username: username, password: password, id: id, client: client(config)}, nil
	})
}

func (t *Kuocai) Kind() string { return "kuocai" }

func (t *Kuocai) Check(ctx context.Context) error { _, err := t.login(ctx); return err }

func (t *Kuocai) Deploy(ctx context.Context, material Material) (Result, error) {
	if _, err := certificate(material); err != nil {
		return Result{}, err
	}
	token, err := t.login(ctx)
	if err != nil {
		return Result{}, err
	}
	payload := map[string]any{"doMainId": t.id, "https": map[string]string{
		"certificate_name": fmt.Sprintf("cert_%d", time.Now().UnixNano()), "certificate_source": "0", "certificate_value": string(material.FullChainPEM),
		"https_status": "on", "private_key": string(material.PrivateKeyPEM),
	}}
	status, content, err := requestJSON(ctx, t.client, http.MethodPost, t.endpoint+"/CdnDomainHttps/httpsConfiguration", map[string]string{"Cookie": "kuocai_cdn_token=" + token}, payload)
	if err != nil {
		return Result{Target: t.Kind(), Location: t.id, Written: true}, err
	}
	if err := kuocaiResponse(status, content, nil); err != nil {
		return Result{Target: t.Kind(), Location: t.id, Written: true}, err
	}
	return Result{Target: t.Kind(), Location: t.id, Written: true}, nil
}

func (t *Kuocai) login(ctx context.Context) (string, error) {
	values := url.Values{"userAccount": {t.username}, "userPwd": {t.password}, "remember": {"true"}}
	status, content, err := request(ctx, t.client, http.MethodPost, t.endpoint+"/login/loginUser",
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, []byte(values.Encode()))
	if err != nil {
		return "", err
	}
	var token string
	if err := kuocaiResponse(status, content, &token); err != nil {
		return "", err
	}
	if token == "" {
		return "", errors.New("Kuocai login did not return a token")
	}
	return token, nil
}

func kuocaiResponse(status int, content []byte, destination any) error {
	var response struct {
		Code string          `json:"code"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(content, &response); err != nil {
		return errors.New("invalid Kuocai API response")
	}
	if status < 200 || status >= 300 || response.Code != "SUCCESS" {
		return fmt.Errorf("Kuocai API rejected request (HTTP %d, code %s)", status, response.Code)
	}
	if destination != nil && json.Unmarshal(response.Data, destination) != nil {
		return errors.New("invalid Kuocai API data")
	}
	return nil
}

var _ Target = (*Kuocai)(nil)
