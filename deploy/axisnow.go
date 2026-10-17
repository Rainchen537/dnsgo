package deploy

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type AxisNow struct {
	endpoint string
	token    string
	uuid     string
	client   *http.Client
}

func init() {
	register("axisnow", func(config Config) (Target, error) {
		endpoint, err := targetEndpoint(config, "https://api.axisnow.io")
		if err != nil {
			return nil, err
		}
		token := strings.TrimSpace(config.Values["token"])
		if token == "" {
			return nil, errors.New("AxisNow token is required")
		}
		return &AxisNow{endpoint: endpoint, token: token, uuid: strings.TrimSpace(config.Values["uuid"]), client: client(config)}, nil
	})
}

func (t *AxisNow) Kind() string { return "axisnow" }

func (t *AxisNow) Check(ctx context.Context) error {
	status, _, err := request(ctx, t.client, http.MethodGet, t.endpoint+"/client/v1/certificates", t.headers(), nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("AxisNow API returned HTTP %d", status)
	}
	return nil
}

func (t *AxisNow) Deploy(ctx context.Context, material Material) (Result, error) {
	leaf, err := certificate(material)
	if err != nil {
		return Result{}, err
	}
	if t.uuid != "" {
		data, err := t.call(ctx, http.MethodGet, "/client/v1/certificates/"+url.PathEscape(t.uuid), nil)
		if err != nil {
			return Result{}, err
		}
		var existing struct {
			Certificate string `json:"certificate"`
		}
		if json.Unmarshal(data, &existing) != nil || existing.Certificate == "" {
			return Result{}, errors.New("AxisNow configured certificate could not be inspected")
		}
		old, err := certificatePEM([]byte(existing.Certificate))
		if err != nil {
			return Result{}, errors.New("AxisNow configured certificate is invalid")
		}
		if sha256.Sum256(old.Raw) == sha256.Sum256(leaf.Raw) {
			return Result{Target: t.Kind(), Location: t.uuid, Written: false}, nil
		}
	}
	name := fmt.Sprintf("%s-%d", strings.TrimPrefix(leaf.Subject.CommonName, "*."), leaf.NotBefore.Unix())
	data, err := t.call(ctx, http.MethodPost, "/client/v1/certificates", map[string]string{
		"type": "upload", "name": name, "certificate": string(material.FullChainPEM), "private_key": string(material.PrivateKeyPEM),
	})
	if err != nil {
		return Result{Target: t.Kind(), Written: true}, err
	}
	var uploaded struct {
		UUID string `json:"uuid"`
	}
	if err := json.Unmarshal(data, &uploaded); err != nil || uploaded.UUID == "" {
		return Result{Target: t.Kind(), Written: true}, errors.New("AxisNow uploaded certificate but did not return UUID")
	}
	return Result{Target: t.Kind(), Location: uploaded.UUID, Written: true}, nil
}

func (t *AxisNow) headers() map[string]string {
	return map[string]string{"Accept": "application/json", "Authorization": "Bearer " + t.token}
}

func (t *AxisNow) call(ctx context.Context, method, path string, payload any) (json.RawMessage, error) {
	status, content, err := requestJSON(ctx, t.client, method, t.endpoint+path, t.headers(), payload)
	if err != nil {
		return nil, err
	}
	var response struct {
		Success bool            `json:"success"`
		Result  json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(content, &response); err != nil {
		return nil, requestOutcomeError(t.Kind(), method, "invalid AxisNow API response")
	}
	if status < 200 || status >= 300 || !response.Success {
		return nil, fmt.Errorf("AxisNow API rejected request (HTTP %d)", status)
	}
	return response.Result, nil
}

var _ Target = (*AxisNow)(nil)
