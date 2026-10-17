package deploy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/rainchen537/dnsgo"
	"github.com/rainchen537/dnsgo/internal/volc"
)

type Huoshan struct {
	keyID         string
	secret        string
	product       string
	domains       []string
	projectName   string
	bucketDomain  string
	listenerID    string
	vodSpace      string
	vodDomainType string
	client        *http.Client
}

func init() {
	register("huoshan", func(config Config) (Target, error) {
		keyID, secret := strings.TrimSpace(config.Values["AccessKeyId"]), config.Values["SecretAccessKey"]
		if keyID == "" || secret == "" {
			return nil, errors.New("Volcengine access keys are required")
		}
		product := strings.TrimSpace(config.Values["product"])
		if product == "" {
			product = "cdn"
		}
		switch product {
		case "cdn", "dcdn", "tos", "live", "vod", "imagex", "clb", "alb", "upload":
		default:
			return nil, errors.New("unknown Volcengine deployment product")
		}
		target := &Huoshan{keyID: keyID, secret: secret, product: product, domains: splitList(config.Values["domain"]),
			projectName: config.Values["project_name"], bucketDomain: config.Values["bucket_domain"], listenerID: config.Values["listener_id"],
			vodSpace: config.Values["vod_space_name"], vodDomainType: config.Values["vod_domain_type"], client: client(config)}
		if product != "clb" && product != "alb" && product != "upload" && len(target.domains) == 0 {
			return nil, errors.New("Volcengine deployment domains are required")
		}
		if (product == "clb" || product == "alb") && target.listenerID == "" {
			return nil, errors.New("Volcengine listener ID is required")
		}
		if product == "tos" && target.bucketDomain == "" {
			return nil, errors.New("Volcengine TOS bucket domain is required")
		}
		if product == "vod" && (target.vodSpace == "" || target.vodDomainType == "") {
			return nil, errors.New("Volcengine VOD space and domain type are required")
		}
		return target, nil
	})
}

func (t *Huoshan) Kind() string { return "huoshan" }

func (t *Huoshan) api(endpoint, service, version, region string) volc.Client {
	return volc.Client{KeyID: t.keyID, Secret: t.secret, Endpoint: endpoint, Service: service, Version: version, Region: region, HTTP: t.client}
}

func (t *Huoshan) Check(ctx context.Context) error {
	client := t.api("open.volcengineapi.com", "cdn", "2021-03-01", "cn-north-1")
	return client.Call(ctx, http.MethodPost, "ListCertInfo", map[string]any{"Source": "volc_cert_center"}, nil)
}

func (t *Huoshan) Deploy(ctx context.Context, material Material) (Result, error) {
	if _, err := certificate(material); err != nil {
		return Result{}, err
	}
	if t.product == "live" {
		return t.deployLive(ctx, material)
	}
	id, imported, err := t.importCert(ctx, material)
	result := Result{Target: t.Kind(), Location: id, Written: imported}
	if err != nil {
		return result, err
	}
	if t.product == "upload" {
		return result, nil
	}
	// The following operations may update one or more resources before a
	// later request or readback fails, even when ImportCertificate reused an
	// existing certificate. Require a target readback before retrying.
	result.Written = true
	switch t.product {
	case "cdn":
		err = t.deployCDN(ctx, id)
	case "dcdn":
		client := t.api("open.volcengineapi.com", "dcdn", "2021-04-01", "cn-north-1")
		err = client.Call(ctx, http.MethodPost, "CreateCertBind", map[string]any{"CertId": id, "DomainNames": t.domains}, nil)
		if err == nil {
			result.Pending = true
			result.Metadata = map[string]string{"product": "dcdn"}
		}
	case "tos":
		err = t.deployTOS(ctx, id)
	case "imagex":
		err = t.deployImageX(ctx, id)
	case "clb", "alb":
		client := t.api("open.volcengineapi.com", t.product, "2020-04-01", "cn-beijing")
		err = client.Call(ctx, http.MethodGet, "ModifyListenerAttributes", map[string]any{
			"ListenerId": t.listenerID, "CertificateSource": "cert_center", "CertCenterCertificateId": id,
		}, nil)
	case "vod":
		err = t.deployVOD(ctx, id)
	}
	if err != nil {
		return result, err
	}
	return result, nil
}

// Poll confirms each requested DCDN domain has deployed the certificate.
// CreateCertBind only accepts a binding request; propagation is asynchronous.
func (t *Huoshan) Poll(ctx context.Context, result Result) (Result, error) {
	if t.product != "dcdn" || !result.Pending || result.Location == "" ||
		result.Metadata == nil || result.Metadata["product"] != "dcdn" {
		return result, &dnsgo.Error{Provider: t.Kind(), Operation: "poll_deployment", Code: dnsgo.CodeConflict,
			Message: "Volcengine DCDN pending result does not match configuration"}
	}
	client := t.api("open.volcengineapi.com", "dcdn", "2021-04-01", "cn-north-1")
	var response struct {
		BindList []struct {
			CertID       string `json:"CertId"`
			DomainName   string `json:"DomainName"`
			DeployStatus string `json:"DeployStatus"`
		} `json:"BindList"`
	}
	if err := client.Call(ctx, http.MethodPost, "ListCertBind", map[string]any{"SearchKey": result.Location}, &response); err != nil {
		return result, err
	}
	statuses := make(map[string]string, len(response.BindList))
	for _, binding := range response.BindList {
		if binding.CertID == result.Location {
			name := strings.ToLower(strings.TrimSuffix(binding.DomainName, "."))
			if previous, exists := statuses[name]; exists && previous != binding.DeployStatus {
				return result, &dnsgo.Error{Provider: t.Kind(), Operation: "poll_deployment", Code: dnsgo.CodeResultUnknown,
					Message: "Volcengine DCDN returned conflicting certificate binding statuses"}
			}
			statuses[name] = binding.DeployStatus
		}
	}
	pending := false
	for _, domain := range t.domains {
		status, ok := statuses[strings.ToLower(strings.TrimSuffix(domain, "."))]
		if !ok || status == "Waiting" {
			pending = true
			continue
		}
		if status != "Deployed" {
			return result, &dnsgo.Error{Provider: t.Kind(), Operation: "poll_deployment", Code: dnsgo.CodeResultUnknown,
				Message: "Volcengine DCDN reported an unexpected certificate deployment status"}
		}
	}
	result.Pending = pending
	return result, nil
}

func (t *Huoshan) importCert(ctx context.Context, material Material) (string, bool, error) {
	leaf, _ := certificate(material)
	name := fmt.Sprintf("%s-%d", strings.TrimPrefix(leaf.Subject.CommonName, "*."), leaf.NotBefore.Unix())
	params := map[string]any{"Tag": name, "Repeatable": false, "CertificateInfo": map[string]string{
		"CertificateChain": string(material.FullChainPEM), "PrivateKey": string(material.PrivateKeyPEM),
	}}
	if t.projectName != "" {
		params["ProjectName"] = t.projectName
	}
	client := t.api("certificate-service.volcengineapi.com", "certificate_service", "2024-10-01", "cn-beijing")
	var response struct {
		InstanceID string `json:"InstanceId"`
		RepeatID   string `json:"RepeatId"`
	}
	if err := client.Call(ctx, http.MethodPost, "ImportCertificate", params, &response); err != nil {
		return "", false, err
	}
	if response.InstanceID == "" {
		if response.RepeatID == "" {
			return "", true, errors.New("Volcengine certificate import returned no ID")
		}
		return response.RepeatID, false, nil
	}
	if err := waitContext(ctx, time.Second); err != nil {
		return response.InstanceID, true, err
	}
	if err := client.Call(ctx, http.MethodPost, "CertificateUpdateInstance", map[string]any{
		"InstanceId": response.InstanceID, "Options": map[string]string{"ExpiredNotice": "Disabled"},
	}, nil); err != nil {
		return response.InstanceID, true, err
	}
	return response.InstanceID, true, nil
}

func (t *Huoshan) deployCDN(ctx context.Context, id string) error {
	client := t.api("cdn.volcengineapi.com", "cdn", "2021-03-01", "cn-north-1")
	for offset := 0; offset < len(t.domains); offset += 50 {
		end := offset + 50
		if end > len(t.domains) {
			end = len(t.domains)
		}
		batch := t.domains[offset:end]
		var response struct {
			DeployResult []struct {
				Domain string `json:"Domain"`
				Status string `json:"Status"`
			} `json:"DeployResult"`
		}
		if err := client.Call(ctx, http.MethodPost, "BatchDeployCert", map[string]any{
			"CertId": id, "Domain": strings.Join(batch, ",")}, &response); err != nil {
			return err
		}
		wanted := map[string]bool{}
		for _, domain := range batch {
			wanted[strings.ToLower(domain)] = true
		}
		succeeded := map[string]bool{}
		for _, row := range response.DeployResult {
			name := strings.ToLower(row.Domain)
			if !wanted[name] {
				continue
			}
			if row.Status != "success" {
				return errors.New("Volcengine CDN deployment reported a failed domain")
			}
			succeeded[name] = true
		}
		if len(succeeded) != len(wanted) {
			return errors.New("Volcengine CDN deployment did not confirm every requested domain")
		}
	}
	return nil
}

func (t *Huoshan) deployLive(ctx context.Context, material Material) (Result, error) {
	leaf, _ := certificate(material)
	name := fmt.Sprintf("%s-%d", strings.TrimPrefix(leaf.Subject.CommonName, "*."), leaf.NotBefore.Unix())
	client := t.api("live.volcengineapi.com", "live", "2023-01-01", "cn-north-1")
	params := map[string]any{"CertName": name, "Rsa": map[string]string{"Pubkey": string(material.FullChainPEM), "Prikey": string(material.PrivateKeyPEM)}, "UseWay": "https"}
	if t.projectName != "" {
		params["ProjectName"] = t.projectName
	}
	var created struct {
		ChainID string `json:"ChainID"`
	}
	if err := client.Call(ctx, http.MethodPost, "CreateCert", params, &created); err != nil {
		return Result{Target: t.Kind(), Written: true}, err
	}
	if created.ChainID == "" {
		return Result{Target: t.Kind(), Written: true}, errors.New("Volcengine live certificate returned no ChainID")
	}
	result := Result{Target: t.Kind(), Location: created.ChainID, Written: true}
	for _, domain := range t.domains {
		if err := client.Call(ctx, http.MethodPost, "BindCert", map[string]any{
			"ChainID": created.ChainID, "Domain": domain, "HTTPS": true, "HTTP2": true,
		}, nil); err != nil {
			return result, err
		}
	}
	return result, nil
}

func (t *Huoshan) deployImageX(ctx context.Context, id string) error {
	client := t.api("imagex.volcengineapi.com", "imagex", "2018-08-01", "cn-north-1")
	for _, domain := range t.domains {
		var response struct {
			SuccessDomains []json.RawMessage `json:"SuccessDomains"`
			FailedDomains  []json.RawMessage `json:"FailedDomains"`
		}
		if err := client.Call(ctx, http.MethodPost, "UpdateImageBatchDomainCert", []map[string]string{{"domain": domain, "cert_id": id}}, &response); err != nil {
			return err
		}
		if len(response.SuccessDomains) == 0 {
			return errors.New("Volcengine ImageX domain certificate deployment failed")
		}
	}
	return nil
}

func (t *Huoshan) deployVOD(ctx context.Context, id string) error {
	client := t.api("vod.volcengineapi.com", "vod", "2023-07-01", "cn-north-1")
	for _, domain := range t.domains {
		payload := map[string]any{"SpaceName": t.vodSpace, "DomainType": t.vodDomainType, "Domain": domain,
			"Config": map[string]any{"HTTPS": map[string]any{"Switch": true, "CertInfo": map[string]string{"CertId": id}}}}
		if err := client.Call(ctx, http.MethodPost, "UpdateDomainConfig", payload, nil); err != nil {
			return err
		}
	}
	return nil
}

func (t *Huoshan) deployTOS(ctx context.Context, id string) error {
	host := strings.TrimPrefix(strings.TrimPrefix(t.bucketDomain, "https://"), "http://")
	host = strings.TrimRight(host, "/")
	if host == "" || strings.Contains(host, "/") {
		return errors.New("invalid Volcengine TOS bucket domain")
	}
	for _, domain := range t.domains {
		body, err := json.Marshal(map[string]any{"CustomDomainRule": map[string]string{"Domain": domain, "CertId": id}})
		if err != nil {
			return errors.New("encode Volcengine TOS request failed")
		}
		date := time.Now().UTC().Format("20060102T150405Z")
		shortDate := date[:8]
		payloadHash := sha256.Sum256(body)
		headers := map[string]string{"content-type": "application/json", "host": host, "x-tos-content-sha256": hex.EncodeToString(payloadHash[:]), "x-tos-date": date}
		names := make([]string, 0, len(headers))
		for name := range headers {
			names = append(names, name)
		}
		sort.Strings(names)
		var canonicalHeaders strings.Builder
		for _, name := range names {
			canonicalHeaders.WriteString(name + ":" + headers[name] + "\n")
		}
		query := url.Values{"customdomain": {""}}
		canonical := "PUT\n/\ncustomdomain=\n" + canonicalHeaders.String() + "\n" + strings.Join(names, ";") + "\n" + hex.EncodeToString(payloadHash[:])
		canonicalHash := sha256.Sum256([]byte(canonical))
		scope := shortDate + "/cn-beijing/tos/request"
		toSign := "TOS4-HMAC-SHA256\n" + date + "\n" + scope + "\n" + hex.EncodeToString(canonicalHash[:])
		key := ksyunHMAC([]byte(t.secret), shortDate)
		key = ksyunHMAC(key, "cn-beijing")
		key = ksyunHMAC(key, "tos")
		key = ksyunHMAC(key, "request")
		headers["Authorization"] = "TOS4-HMAC-SHA256 Credential=" + t.keyID + "/" + scope + ", SignedHeaders=" + strings.Join(names, ";") + ", Signature=" + hex.EncodeToString(ksyunHMAC(key, toSign))
		status, _, err := request(ctx, t.client, http.MethodPut, "https://"+host+"/?"+query.Encode(), headers, body)
		if err != nil {
			return err
		}
		if err := expectHTTPStatus(status); err != nil {
			return err
		}
	}
	return nil
}

var _ Target = (*Huoshan)(nil)
var _ Poller = (*Huoshan)(nil)
