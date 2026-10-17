package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/rainchen537/dnsgo/internal/ucloud"
)

type UCloud struct {
	client   ucloud.Client
	domainID string
}

func init() {
	register("ucloud", func(config Config) (Target, error) {
		publicKey, privateKey := strings.TrimSpace(config.Values["PublicKey"]), strings.TrimSpace(config.Values["PrivateKey"])
		domainID := strings.TrimSpace(config.Values["domain_id"])
		if publicKey == "" || privateKey == "" || domainID == "" {
			return nil, errors.New("UCloud public key, private key and UCDN domain ID are required")
		}
		return &UCloud{client: ucloud.Client{PublicKey: publicKey, PrivateKey: privateKey, Endpoint: config.Endpoint, HTTP: client(config)}, domainID: domainID}, nil
	})
}

func (t *UCloud) Kind() string { return "ucloud" }

func (t *UCloud) Check(ctx context.Context) error {
	return t.client.Call(ctx, "GetCertificateList", map[string]any{"Mode": "free"}, nil)
}

func (t *UCloud) Deploy(ctx context.Context, material Material) (Result, error) {
	leaf, err := certificate(material)
	if err != nil {
		return Result{}, err
	}
	name := fmt.Sprintf("%s-%d", strings.ReplaceAll(strings.ReplaceAll(leaf.Subject.CommonName, "*", ""), ".", ""), leaf.NotBefore.Unix())
	err = t.client.Call(ctx, "AddCertificate", map[string]any{
		"CertName": name, "UserCert": string(material.FullChainPEM), "PrivateKey": string(material.PrivateKeyPEM),
	}, nil)
	if err != nil && !strings.Contains(strings.ToLower(err.Error()), "cert already exist") {
		return Result{}, err
	}
	result := Result{Target: t.Kind(), Written: err == nil}
	var domains struct {
		DomainList []struct {
			Domain            string `json:"Domain"`
			HttpsStatusCn     string `json:"HttpsStatusCn"`
			HttpsStatusAbroad string `json:"HttpsStatusAbroad"`
			CertNameCn        string `json:"CertNameCn"`
			CertNameAbroad    string `json:"CertNameAbroad"`
		} `json:"DomainList"`
	}
	if err := t.client.Call(ctx, "GetUcdnDomainConfig", map[string]any{"DomainId.0": t.domainID}, &domains); err != nil {
		return result, err
	}
	if len(domains.DomainList) == 0 {
		return result, errors.New("UCloud UCDN domain ID was not found")
	}
	domain := domains.DomainList[0]
	if domain.CertNameCn == name || domain.CertNameAbroad == name {
		result.Location = t.domainID
		return result, nil
	}
	var certificates struct {
		CertList []struct {
			CertName string          `json:"CertName"`
			CertID   json.RawMessage `json:"CertId"`
		} `json:"CertList"`
	}
	if err := t.client.Call(ctx, "GetCertificateBaseInfoList", map[string]any{"Domain": domain.Domain}, &certificates); err != nil {
		return result, err
	}
	var certID string
	for _, cert := range certificates.CertList {
		if cert.CertName == name {
			certID = scalarID(cert.CertID)
			break
		}
	}
	if certID == "" {
		return result, errors.New("UCloud certificate ID could not be resolved")
	}
	result.Location = certID
	params := map[string]any{"DomainId": t.domainID, "CertName": name, "CertId": certID, "CertType": "ucdn"}
	if domain.HttpsStatusCn == "enable" {
		params["HttpsStatusCn"] = "enable"
	}
	if domain.HttpsStatusAbroad == "enable" {
		params["HttpsStatusAbroad"] = "enable"
	}
	if domain.HttpsStatusCn != "enable" && domain.HttpsStatusAbroad != "enable" {
		params["HttpsStatusCn"] = "enable"
	}
	if err := t.client.Call(ctx, "UpdateUcdnDomainHttpsConfigV2", params, nil); err != nil {
		result.Written = true
		return result, err
	}
	result.Written = true
	return result, nil
}

var _ Target = (*UCloud)(nil)
