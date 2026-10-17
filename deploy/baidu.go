package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/rainchen537/dnsgo/internal/bce"
)

type Baidu struct {
	keyID   string
	secret  string
	product string
	domains []string
	blbID   string
	blbPort string
	region  string
	client  *http.Client
}

func init() {
	register("baidu", func(config Config) (Target, error) {
		keyID, secret := strings.TrimSpace(config.Values["AccessKeyId"]), strings.TrimSpace(config.Values["SecretAccessKey"])
		if keyID == "" || secret == "" {
			return nil, errors.New("Baidu access key ID and secret are required")
		}
		product := strings.TrimSpace(config.Values["product"])
		if product == "" {
			product = "cdn"
		}
		if product != "cdn" && product != "blb" && product != "appblb" && product != "upload" {
			return nil, errors.New("unsupported Baidu certificate product")
		}
		result := &Baidu{keyID: keyID, secret: secret, product: product, domains: splitList(config.Values["domain"]),
			blbID: config.Values["blb_id"], blbPort: config.Values["blb_port"], region: config.Values["region"], client: client(config)}
		if product == "cdn" && len(result.domains) == 0 {
			return nil, errors.New("Baidu CDN domains are required")
		}
		if (product == "blb" || product == "appblb") && (result.blbID == "" || result.blbPort == "" || result.region == "") {
			return nil, errors.New("Baidu BLB instance, listener port and region are required")
		}
		return result, nil
	})
}

func (t *Baidu) Kind() string { return "baidu" }

func (t *Baidu) bceClient(host string) bce.Client {
	return bce.Client{KeyID: t.keyID, Secret: t.secret, Endpoint: host, HTTP: t.client}
}

func (t *Baidu) Check(ctx context.Context) error {
	client := t.bceClient("cdn.baidubce.com")
	return client.Call(ctx, http.MethodGet, "/v2/domain", nil, nil, nil)
}

func (t *Baidu) Deploy(ctx context.Context, material Material) (Result, error) {
	leaf, err := certificate(material)
	if err != nil {
		return Result{}, err
	}
	name := fmt.Sprintf("%s-%d", strings.TrimPrefix(leaf.Subject.CommonName, "*."), leaf.NotBefore.Unix())
	if t.product == "cdn" {
		return t.deployCDN(ctx, material, name)
	}
	id, uploaded, err := t.certificateID(ctx, material, name)
	if err != nil {
		return Result{Target: t.Kind(), Written: uploaded}, err
	}
	result := Result{Target: t.Kind(), Location: id, Written: uploaded}
	if t.product == "upload" {
		return result, nil
	}
	client := t.bceClient("blb." + t.region + ".baidubce.com")
	query := url.Values{"listenerPort": {t.blbPort}}
	path := "/v1/" + t.product + "/" + url.PathEscape(t.blbID) + "/HTTPSlistener"
	if err := client.Call(ctx, http.MethodPut, path, query, map[string]any{"certIds": []string{id}}, nil); err != nil {
		return result, err
	}
	result.Written = true
	return result, nil
}

func (t *Baidu) deployCDN(ctx context.Context, material Material, name string) (Result, error) {
	client := t.bceClient("cdn.baidubce.com")
	result := Result{Target: t.Kind()}
	payload := map[string]any{"httpsEnable": "ON", "certificate": map[string]string{
		"certName": name, "certServerData": string(material.FullChainPEM), "certPrivateData": string(material.PrivateKeyPEM),
	}}
	for _, domain := range t.domains {
		path := "/v2/" + url.PathEscape(domain) + "/certificates"
		var existing struct {
			CertName string `json:"certName"`
		}
		if err := client.Call(ctx, http.MethodGet, path, nil, nil, &existing); err == nil && existing.CertName == name {
			continue
		}
		var uploaded struct {
			CertID json.RawMessage `json:"certId"`
		}
		if err := client.Call(ctx, http.MethodPut, path, nil, payload, &uploaded); err != nil {
			return result, err
		}
		result.Written = true
		if result.Location != "" {
			result.Location += ","
		}
		result.Location += domain
		if id := scalarID(uploaded.CertID); id != "" {
			result.Location += ":" + id
		}
	}
	return result, nil
}

func (t *Baidu) certificateID(ctx context.Context, material Material, name string) (string, bool, error) {
	client := t.bceClient("certificate.baidubce.com")
	var list struct {
		Certs []struct {
			CertName string          `json:"certName"`
			CertID   json.RawMessage `json:"certId"`
		} `json:"certs"`
	}
	if err := client.Call(ctx, http.MethodGet, "/v1/certificate", url.Values{"certName": {name}}, nil, &list); err != nil {
		return "", false, err
	}
	for _, item := range list.Certs {
		if item.CertName == name && scalarID(item.CertID) != "" {
			return scalarID(item.CertID), false, nil
		}
	}
	var created struct {
		CertID json.RawMessage `json:"certId"`
	}
	err := client.Call(ctx, http.MethodPost, "/v1/certificate", nil, map[string]string{
		"certName": name, "certServerData": string(material.FullChainPEM), "certPrivateData": string(material.PrivateKeyPEM),
	}, &created)
	if err != nil {
		return "", false, err
	}
	id := scalarID(created.CertID)
	if id == "" {
		return "", true, errors.New("Baidu uploaded certificate but did not return ID")
	}
	return id, true, nil
}

var _ Target = (*Baidu)(nil)
