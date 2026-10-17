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

	"github.com/rainchen537/dnsgo/internal/aliyunrpc"
)

type Aliyun struct {
	keyID   string
	secret  string
	product string
	region  string
	values  map[string]string
	client  *http.Client
}

func init() {
	register("aliyun", func(config Config) (Target, error) {
		keyID, secret := strings.TrimSpace(config.Values["AccessKeyId"]), strings.TrimSpace(config.Values["AccessKeySecret"])
		if keyID == "" || secret == "" {
			return nil, errors.New("Aliyun access key ID and secret are required")
		}
		product := strings.TrimSpace(config.Values["product"])
		if product == "" {
			product = "cdn"
		}
		switch product {
		case "cdn", "dcdn", "esa", "esa_saas", "oss", "waf", "wafres", "waf2", "api", "ddoscoo", "live", "vod", "fc", "fc2", "clb", "alb", "nlb", "ga", "upload":
		default:
			return nil, errors.New("unknown Aliyun deployment product")
		}
		region := strings.TrimSpace(config.Values["region"])
		if region == "" {
			region = "cn-hangzhou"
		}
		return &Aliyun{keyID: keyID, secret: secret, product: product, region: region, values: config.Values, client: client(config)}, nil
	})
}

func (t *Aliyun) Kind() string { return "aliyun" }

func (t *Aliyun) Check(ctx context.Context) error {
	return t.rpc(ctx, "cas.aliyuncs.com", "2020-04-07", http.MethodPost, "ListUserCertificateOrder", nil, nil)
}

func (t *Aliyun) rpc(ctx context.Context, endpoint, version, method, action string, fields map[string]any, output any) error {
	params := url.Values{}
	for name, value := range fields {
		if value != nil {
			params.Set(name, fmt.Sprint(value))
		}
	}
	api := &aliyunrpc.Client{KeyID: t.keyID, Secret: t.secret, Endpoint: "https://" + endpoint, Version: version, HTTP: t.client}
	return api.Call(ctx, method, action, params, output)
}

func (t *Aliyun) Deploy(ctx context.Context, material Material) (Result, error) {
	leaf, err := certificate(material)
	if err != nil {
		return Result{}, err
	}
	name := fmt.Sprintf("%s-%d", strings.TrimPrefix(leaf.Subject.CommonName, "*."), leaf.NotBefore.Unix())
	result := Result{Target: t.Kind(), Metadata: map[string]string{"certificate_name": name}}
	switch t.product {
	case "api":
		return t.deployAPI(ctx, material, name)
	case "vod":
		return t.deployVOD(ctx, material)
	case "fc", "fc2":
		return t.deployFC(ctx, material, name)
	}
	id, actualName, uploaded, err := t.certificateID(ctx, material, name, strings.ToLower(leaf.SerialNumber.Text(16)))
	result.Location, result.Written = id, uploaded
	result.Metadata["certificate_name"] = actualName
	if err != nil {
		return result, err
	}
	if t.product == "upload" {
		return result, nil
	}
	switch t.product {
	case "cdn", "dcdn", "live":
		err = t.deployEdgeDomains(ctx, id, actualName, &result)
	case "ddoscoo":
		err = t.deployDDoS(ctx, id, &result)
	case "esa":
		err = t.deployESA(ctx, id, actualName, &result)
	case "esa_saas":
		err = t.deployESASaaS(ctx, id, &result)
	case "oss":
		err = t.deployOSS(ctx, id, &result)
	case "waf":
		err = t.deployWAF(ctx, id, &result)
	case "wafres":
		err = t.deployWAFResource(ctx, id, &result)
	case "waf2":
		err = t.deployWAF2(ctx, id, &result)
	case "clb":
		err = t.deployCLB(ctx, id, actualName, &result)
	case "alb", "nlb":
		err = t.deployALBorNLB(ctx, id, &result)
	case "ga":
		err = t.deployGA(ctx, id, &result)
	}
	return result, err
}

func (t *Aliyun) certificateID(ctx context.Context, material Material, name, serial string) (string, string, bool, error) {
	leaf, _ := certificate(material)
	endpoint := "cas.aliyuncs.com"
	if t.region == "ap-southeast-1" {
		endpoint = "cas.ap-southeast-1.aliyuncs.com"
	}
	const pageSize = 50
	seen := 0
	for page := 1; page <= 100; page++ {
		var listing struct {
			TotalCount   int `json:"TotalCount"`
			Certificates []struct {
				CertificateID json.RawMessage `json:"CertificateId"`
				SerialNo      string          `json:"SerialNo"`
				Name          string          `json:"Name"`
			} `json:"CertificateOrderList"`
		}
		err := t.rpc(ctx, endpoint, "2020-04-07", http.MethodPost, "ListUserCertificateOrder", map[string]any{
			"Keyword": leaf.Subject.CommonName, "OrderType": "CERT", "CurrentPage": page, "ShowSize": pageSize,
		}, &listing)
		if err != nil {
			return "", name, false, err
		}
		for _, item := range listing.Certificates {
			if normalizeCertSerial(item.SerialNo) != "" && normalizeCertSerial(item.SerialNo) == normalizeCertSerial(serial) {
				id := scalarID(item.CertificateID)
				if id != "" {
					if item.Name != "" {
						name = item.Name
					}
					return id, name, false, nil
				}
			}
		}
		seen += len(listing.Certificates)
		if listing.TotalCount > 0 && seen >= listing.TotalCount ||
			listing.TotalCount == 0 && len(listing.Certificates) < pageSize {
			break
		}
		if len(listing.Certificates) == 0 {
			return "", name, false, errors.New("Aliyun CAS certificate search returned an incomplete page")
		}
		if page == 100 {
			return "", name, false, errors.New("Aliyun CAS certificate search exceeded 100 pages; upload was not attempted")
		}
	}
	var uploaded struct {
		CertID json.RawMessage `json:"CertId"`
	}
	err := t.rpc(ctx, endpoint, "2020-04-07", http.MethodPost, "UploadUserCertificate", map[string]any{
		"Name": name, "Cert": string(material.FullChainPEM), "Key": string(material.PrivateKeyPEM),
	}, &uploaded)
	if err != nil {
		return "", name, false, err
	}
	id := scalarID(uploaded.CertID)
	if id == "" {
		return "", name, true, errors.New("Aliyun CAS uploaded certificate but returned no ID")
	}
	if err := waitContext(ctx, 500*time.Millisecond); err != nil {
		return id, name, true, err
	}
	return id, name, true, nil
}

func normalizeCertSerial(value string) string {
	var serial strings.Builder
	for _, char := range strings.ToLower(value) {
		switch {
		case char >= '0' && char <= '9', char >= 'a' && char <= 'f':
			serial.WriteRune(char)
		case char == ':' || char == '-' || char == ' ':
		default:
			return ""
		}
	}
	return strings.TrimLeft(serial.String(), "0")
}

func (t *Aliyun) deployEdgeDomains(ctx context.Context, id, name string, result *Result) error {
	domains := splitList(t.values["domain"])
	if len(domains) == 0 {
		return errors.New("Aliyun deployment domains are required")
	}
	endpoint, version, action := "cdn.aliyuncs.com", "2018-05-10", "SetCdnDomainSSLCertificate"
	if t.product == "dcdn" {
		endpoint, version, action = "dcdn.aliyuncs.com", "2018-01-15", "SetDcdnDomainSSLCertificate"
	}
	if t.product == "live" {
		endpoint, version, action = "live.aliyuncs.com", "2016-11-01", "SetLiveDomainCertificate"
	}
	for _, domain := range domains {
		if err := t.rpc(ctx, endpoint, version, http.MethodPost, action, map[string]any{
			"DomainName": domain, "CertName": name, "CertType": "cas", "SSLProtocol": "on", "CertId": id,
		}, nil); err != nil {
			return err
		}
		result.Written = true
	}
	return nil
}

func (t *Aliyun) deployAPI(ctx context.Context, material Material, name string) (Result, error) {
	groupID, region := t.values["api_groupid"], t.values["regionid"]
	domains := splitList(t.values["domain"])
	if groupID == "" || region == "" || len(domains) == 0 {
		return Result{}, errors.New("Aliyun API Gateway group, region and domains are required")
	}
	result := Result{Target: t.Kind()}
	for _, domain := range domains {
		err := t.rpc(ctx, "apigateway."+region+".aliyuncs.com", "2016-07-14", http.MethodPost, "SetDomainCertificate", map[string]any{
			"GroupId": groupID, "DomainName": domain, "CertificateName": name, "CertificateBody": string(material.FullChainPEM),
			"CertificatePrivateKey": string(material.PrivateKeyPEM),
		}, nil)
		if err != nil {
			return result, err
		}
		result.Written = true
		if result.Location != "" {
			result.Location += ","
		}
		result.Location += domain
	}
	return result, nil
}

func (t *Aliyun) deployVOD(ctx context.Context, material Material) (Result, error) {
	domains := splitList(t.values["domain"])
	if len(domains) == 0 {
		return Result{}, errors.New("Aliyun VOD domains are required")
	}
	result := Result{Target: t.Kind()}
	for _, domain := range domains {
		err := t.rpc(ctx, "vod.cn-shanghai.aliyuncs.com", "2017-03-21", http.MethodPost, "SetVodDomainCertificate", map[string]any{
			"DomainName": domain, "SSLProtocol": "on", "SSLPub": string(material.FullChainPEM), "SSLPri": string(material.PrivateKeyPEM),
		}, nil)
		if err != nil {
			return result, err
		}
		result.Written = true
		if result.Location != "" {
			result.Location += ","
		}
		result.Location += domain
	}
	return result, nil
}

func (t *Aliyun) deployDDoS(ctx context.Context, id string, result *Result) error {
	domains := splitList(t.values["domain"])
	if len(domains) == 0 {
		return errors.New("Aliyun DDoS domains are required")
	}
	for _, domain := range domains {
		if err := t.rpc(ctx, "ddoscoo."+t.region+".aliyuncs.com", "2020-01-01", http.MethodPost, "AssociateWebCert", map[string]any{
			"Domain": domain, "CertId": id,
		}, nil); err != nil {
			return err
		}
		result.Written = true
	}
	return nil
}

var _ Target = (*Aliyun)(nil)
