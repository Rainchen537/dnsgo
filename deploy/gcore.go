package deploy

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

type Gcore struct {
	endpoint string
	apiKey   string
	id       string
	name     string
	client   *http.Client
}

func init() {
	register("gcore", func(config Config) (Target, error) {
		endpoint, err := targetEndpoint(config, "https://api.gcore.com")
		if err != nil {
			return nil, err
		}
		key := strings.TrimSpace(config.Values["apikey"])
		id := strings.TrimSpace(config.Values["id"])
		if key == "" || id == "" {
			return nil, errors.New("Gcore API token and certificate ID are required")
		}
		return &Gcore{endpoint: endpoint, apiKey: key, id: id, name: config.Values["name"], client: client(config)}, nil
	})
}

func (t *Gcore) Kind() string { return "gcore" }

func (t *Gcore) Check(ctx context.Context) error {
	status, _, err := request(ctx, t.client, http.MethodGet, t.endpoint+"/iam/clients/me", t.headers(), nil)
	if err != nil {
		return err
	}
	return expectHTTPStatus(status)
}

func (t *Gcore) Deploy(ctx context.Context, material Material) (Result, error) {
	if _, err := certificate(material); err != nil {
		return Result{}, err
	}
	status, _, err := requestJSON(ctx, t.client, http.MethodPut, t.endpoint+"/cdn/sslData/"+url.PathEscape(t.id), t.headers(), map[string]any{
		"name": t.name, "sslCertificate": string(material.FullChainPEM), "sslPrivateKey": string(material.PrivateKeyPEM), "validate_root_ca": true,
	})
	if err != nil {
		return Result{}, err
	}
	if err := expectHTTPStatus(status); err != nil {
		return Result{}, err
	}
	return Result{Target: t.Kind(), Location: t.id, Written: true}, nil
}

func (t *Gcore) headers() map[string]string {
	return map[string]string{"Authorization": "APIKey " + t.apiKey}
}

var _ Target = (*Gcore)(nil)
