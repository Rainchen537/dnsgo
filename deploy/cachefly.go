package deploy

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

type CacheFly struct {
	endpoint string
	apiKey   string
	client   *http.Client
}

func init() {
	register("cachefly", func(config Config) (Target, error) {
		endpoint, err := targetEndpoint(config, "https://api.cachefly.com/api/2.5")
		if err != nil {
			return nil, err
		}
		key := strings.TrimSpace(config.Values["apikey"])
		if key == "" {
			return nil, errors.New("CacheFly API token is required")
		}
		return &CacheFly{endpoint: endpoint, apiKey: key, client: client(config)}, nil
	})
}

func (t *CacheFly) Kind() string { return "cachefly" }

func (t *CacheFly) Check(ctx context.Context) error {
	status, _, err := request(ctx, t.client, http.MethodGet, t.endpoint+"/accounts/me", t.headers(), nil)
	if err != nil {
		return err
	}
	return expectHTTPStatus(status)
}

func (t *CacheFly) Deploy(ctx context.Context, material Material) (Result, error) {
	if _, err := certificate(material); err != nil {
		return Result{}, err
	}
	status, _, err := requestJSON(ctx, t.client, http.MethodPost, t.endpoint+"/certificates", t.headers(), map[string]string{
		"certificate": string(material.FullChainPEM), "certificateKey": string(material.PrivateKeyPEM),
	})
	if err != nil {
		return Result{}, err
	}
	if err := expectHTTPStatus(status); err != nil {
		return Result{}, err
	}
	return Result{Target: t.Kind(), Location: "certificates", Written: true}, nil
}

func (t *CacheFly) headers() map[string]string {
	return map[string]string{"x-cf-authorization": "Bearer " + t.apiKey}
}

var _ Target = (*CacheFly)(nil)
