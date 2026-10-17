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

type Baishan struct {
	endpoint string
	token    string
	id       string
	client   *http.Client
}

func init() {
	register("baishan", func(config Config) (Target, error) {
		endpoint, err := targetEndpoint(config, "https://cdn.api.baishan.com")
		if err != nil {
			return nil, err
		}
		token, id := strings.TrimSpace(config.Values["token"]), strings.TrimSpace(config.Values["id"])
		if token == "" || id == "" {
			return nil, errors.New("Baishan token and certificate ID are required")
		}
		return &Baishan{endpoint: endpoint, token: token, id: id, client: client(config)}, nil
	})
}

func (t *Baishan) Kind() string { return "baishan" }

func (t *Baishan) Check(ctx context.Context) error { return ctx.Err() }

func (t *Baishan) Deploy(ctx context.Context, material Material) (Result, error) {
	leaf, err := certificate(material)
	if err != nil {
		return Result{}, err
	}
	name := strings.TrimPrefix(leaf.Subject.CommonName, "*.")
	if name == "" {
		return Result{}, errors.New("Baishan certificate needs a subject common name")
	}
	name = fmt.Sprintf("%s-%d", name, leaf.NotBefore.Unix())
	endpoint := t.endpoint + "/v2/domain/certificate?token=" + url.QueryEscape(t.token)
	status, content, err := requestJSON(ctx, t.client, http.MethodPost, endpoint, nil, map[string]string{
		"cert_id": t.id, "name": name, "certificate": string(material.FullChainPEM), "key": string(material.PrivateKeyPEM),
	})
	if err != nil {
		return Result{}, err
	}
	var result struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(content, &result); err != nil {
		return Result{Target: t.Kind(), Location: t.id, Written: true}, errors.New("invalid Baishan API response")
	}
	if status >= 200 && status < 300 && result.Code == 0 {
		return Result{Target: t.Kind(), Location: t.id, Written: true}, nil
	}
	if strings.Contains(result.Message, "this certificate is exists") {
		return Result{Target: t.Kind(), Location: t.id, Written: false}, nil
	}
	return Result{}, fmt.Errorf("Baishan API rejected certificate (HTTP %d, code %d)", status, result.Code)
}

var _ Target = (*Baishan)(nil)
