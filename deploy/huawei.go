package deploy

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rainchen537/dnsgo/internal/huaweicloud"
)

type Huawei struct {
	keyID       string
	secret      string
	product     string
	domains     []string
	projectID   string
	regionID    string
	certID      string
	obsEndpoint string
	obsBucket   string
	client      *http.Client
}

func init() {
	register("huawei", func(config Config) (Target, error) {
		keyID, secret := strings.TrimSpace(config.Values["AccessKeyId"]), config.Values["SecretAccessKey"]
		if keyID == "" || secret == "" {
			return nil, errors.New("Huawei access keys are required")
		}
		product := strings.TrimSpace(config.Values["product"])
		if product != "cdn" && product != "elb" && product != "waf" && product != "obs" && product != "upload" {
			return nil, errors.New("unknown Huawei deployment product")
		}
		target := &Huawei{keyID: keyID, secret: secret, product: product, domains: splitList(config.Values["domain"]),
			projectID: config.Values["project_id"], regionID: config.Values["region_id"], certID: config.Values["cert_id"],
			obsEndpoint: config.Values["obs_endpoint"], obsBucket: config.Values["obs_bucket"], client: client(config)}
		if (product == "cdn" || product == "obs") && len(target.domains) == 0 {
			return nil, errors.New("Huawei deployment domains are required")
		}
		if (product == "elb" || product == "waf") && (target.projectID == "" || target.regionID == "" || target.certID == "") {
			return nil, errors.New("Huawei project, region and certificate ID are required")
		}
		if product == "obs" && (target.obsEndpoint == "" || target.obsBucket == "") {
			return nil, errors.New("Huawei OBS endpoint and bucket are required")
		}
		return target, nil
	})
}

func (t *Huawei) Kind() string { return "huawei" }

func (t *Huawei) api(endpoint string) huaweicloud.Client {
	return huaweicloud.Client{KeyID: t.keyID, Secret: t.secret, Endpoint: endpoint, HTTP: t.client}
}

func (t *Huawei) Check(ctx context.Context) error {
	client := t.api("scm.cn-north-4.myhuaweicloud.com")
	return client.Call(ctx, http.MethodGet, "/v3/scm/certificates", nil, nil, nil)
}

func (t *Huawei) Deploy(ctx context.Context, material Material) (Result, error) {
	leaf, err := certificate(material)
	if err != nil {
		return Result{}, err
	}
	name := fmt.Sprintf("%s-%d", strings.TrimPrefix(leaf.Subject.CommonName, "*."), leaf.NotBefore.Unix())
	switch t.product {
	case "cdn":
		return t.deployCDN(ctx, material, name)
	case "elb":
		domains := append([]string(nil), leaf.DNSNames...)
		if len(domains) == 0 && leaf.Subject.CommonName != "" {
			domains = []string{leaf.Subject.CommonName}
		}
		if len(domains) == 0 {
			return Result{}, errors.New("Huawei ELB certificate has no DNS names")
		}
		return t.deployELB(ctx, material, domains)
	case "waf":
		return t.deployWAF(ctx, material, name)
	case "obs":
		return t.deployOBS(ctx, material, name)
	case "upload":
		client := t.api("scm.cn-north-4.myhuaweicloud.com")
		var created struct {
			CertificateID string `json:"certificate_id"`
		}
		err := client.Call(ctx, http.MethodPost, "/v3/scm/certificates/import", nil, map[string]string{
			"name": name, "certificate": string(material.FullChainPEM), "private_key": string(material.PrivateKeyPEM),
		}, &created)
		if err != nil {
			return Result{}, err
		}
		if created.CertificateID == "" {
			return Result{Target: t.Kind(), Written: true}, errors.New("Huawei SCM uploaded certificate but returned no ID")
		}
		return Result{Target: t.Kind(), Location: created.CertificateID, Written: true}, nil
	}
	return Result{}, errors.New("unsupported Huawei product")
}

func (t *Huawei) deployCDN(ctx context.Context, material Material, name string) (Result, error) {
	client := t.api("cdn.myhuaweicloud.com")
	payload := map[string]any{"configs": map[string]any{"https": map[string]any{
		"https_status": "on", "certificate_type": "server", "certificate_source": 0, "certificate_name": name,
		"certificate_value": string(material.FullChainPEM), "private_key": string(material.PrivateKeyPEM),
	}}}
	result := Result{Target: t.Kind()}
	for _, domain := range t.domains {
		path := "/v1.1/cdn/configuration/domains/" + url.PathEscape(domain) + "/configs"
		if err := client.Call(ctx, http.MethodPut, path, nil, payload, nil); err != nil {
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

func (t *Huawei) deployELB(ctx context.Context, material Material, domains []string) (Result, error) {
	client := t.api("elb." + t.regionID + ".myhuaweicloud.com")
	path := "/v3/" + url.PathEscape(t.projectID) + "/elb/certificates/" + url.PathEscape(t.certID)
	var current struct {
		Certificate struct {
			Certificate string `json:"certificate"`
		} `json:"certificate"`
	}
	if err := client.Call(ctx, http.MethodGet, path, nil, nil, &current); err != nil {
		return Result{}, err
	}
	if strings.TrimSpace(current.Certificate.Certificate) == strings.TrimSpace(string(material.FullChainPEM)) {
		return Result{Target: t.Kind(), Location: t.certID, Written: false}, nil
	}
	values := map[string]any{"certificate": map[string]string{"certificate": string(material.FullChainPEM),
		"private_key": string(material.PrivateKeyPEM), "domain": strings.Join(domains, ",")}}
	if err := client.Call(ctx, http.MethodPut, path, nil, values, nil); err != nil {
		return Result{}, err
	}
	return Result{Target: t.Kind(), Location: t.certID, Written: true}, nil
}

func (t *Huawei) deployWAF(ctx context.Context, material Material, name string) (Result, error) {
	client := t.api("waf." + t.regionID + ".myhuaweicloud.com")
	path := "/v1/" + url.PathEscape(t.projectID) + "/waf/certificates/" + url.PathEscape(t.certID)
	var current struct {
		Content string `json:"content"`
	}
	if err := client.Call(ctx, http.MethodGet, path, nil, nil, &current); err != nil {
		return Result{}, err
	}
	if strings.TrimSpace(current.Content) == strings.TrimSpace(string(material.FullChainPEM)) {
		return Result{Target: t.Kind(), Location: t.certID, Written: false}, nil
	}
	if err := client.Call(ctx, http.MethodPut, path, nil, map[string]string{
		"name": name, "content": string(material.FullChainPEM), "key": string(material.PrivateKeyPEM),
	}, nil); err != nil {
		return Result{}, err
	}
	return Result{Target: t.Kind(), Location: t.certID, Written: true}, nil
}

func (t *Huawei) deployOBS(ctx context.Context, material Material, name string) (Result, error) {
	endpoint := strings.TrimPrefix(strings.TrimPrefix(t.obsEndpoint, "https://"), "http://")
	endpoint = strings.TrimRight(endpoint, "/")
	if endpoint == "" || strings.Contains(endpoint, "/") || strings.Contains(t.obsBucket, "/") {
		return Result{}, errors.New("invalid Huawei OBS endpoint or bucket")
	}
	body, err := xml.Marshal(struct {
		XMLName     xml.Name `xml:"CustomDomainConfiguration"`
		Name        string   `xml:"Name"`
		Certificate string   `xml:"Certificate"`
		PrivateKey  string   `xml:"PrivateKey"`
	}{Name: name, Certificate: string(material.FullChainPEM), PrivateKey: string(material.PrivateKeyPEM)})
	if err != nil {
		return Result{}, errors.New("encode Huawei OBS certificate failed")
	}
	body = append([]byte(xml.Header), body...)
	result := Result{Target: t.Kind()}
	for _, domain := range t.domains {
		date := time.Now().UTC().Format(http.TimeFormat)
		md5sum := md5.Sum(body)
		contentMD5 := base64.StdEncoding.EncodeToString(md5sum[:])
		toSign := "PUT\n" + contentMD5 + "\napplication/xml\n" + date + "\n/" + t.obsBucket + "/?customdomain=" + domain
		mac := hmac.New(sha1.New, []byte(t.secret))
		_, _ = mac.Write([]byte(toSign))
		address := "https://" + t.obsBucket + "." + endpoint + "/?customdomain=" + url.QueryEscape(domain)
		status, _, err := request(ctx, t.client, http.MethodPut, address, map[string]string{
			"Content-Type": "application/xml", "Content-MD5": contentMD5, "Date": date,
			"Authorization": "OBS " + t.keyID + ":" + base64.StdEncoding.EncodeToString(mac.Sum(nil)),
		}, body)
		if err != nil {
			return result, err
		}
		if err := expectHTTPStatus(status); err != nil {
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

var _ Target = (*Huawei)(nil)
