package deploy

import (
	"context"
	"crypto/hmac"
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
)

type Ksyun struct {
	endpoint string
	keyID    string
	secret   string
	domains  []string
	client   *http.Client
}

func init() {
	register("ksyun", func(config Config) (Target, error) {
		endpoint, err := targetEndpoint(config, "https://cdn.api.ksyun.com")
		if err != nil {
			return nil, err
		}
		keyID, secret := strings.TrimSpace(config.Values["AccessKeyId"]), config.Values["SecretAccessKey"]
		domains := splitList(config.Values["domain"])
		if keyID == "" || secret == "" || len(domains) == 0 {
			return nil, errors.New("Ksyun access keys and CDN domains are required")
		}
		return &Ksyun{endpoint: endpoint, keyID: keyID, secret: secret, domains: domains, client: client(config)}, nil
	})
}

func (t *Ksyun) Kind() string { return "ksyun" }

func (t *Ksyun) Check(ctx context.Context) error {
	_, err := t.call(ctx, http.MethodGet, "GetCertificates", "2016-09-01", "/2016-09-01/cert/GetCertificates", nil)
	return err
}

func (t *Ksyun) Deploy(ctx context.Context, material Material) (Result, error) {
	leaf, err := certificate(material)
	if err != nil {
		return Result{}, err
	}
	name := fmt.Sprintf("%s-%d", strings.TrimPrefix(leaf.Subject.CommonName, "*."), leaf.NotBefore.Unix())
	wanted := map[string]bool{}
	for _, domain := range t.domains {
		wanted[domain] = true
	}
	ids := []string{}
	seen := map[string]bool{}
	for page := 1; page <= 1000 && len(seen) < len(wanted); page++ {
		data, err := t.call(ctx, http.MethodGet, "GetCdnDomains", "2019-06-01", "/2019-06-01/domain/GetCdnDomains", map[string]any{
			"PageSize": 100, "PageNumber": page,
		})
		if err != nil {
			return Result{}, err
		}
		var listing struct {
			Domains []struct {
				DomainName string          `json:"DomainName"`
				DomainID   json.RawMessage `json:"DomainId"`
			} `json:"Domains"`
		}
		if err := json.Unmarshal(data, &listing); err != nil {
			return Result{}, errors.New("invalid Ksyun CDN domain list")
		}
		for _, item := range listing.Domains {
			if wanted[item.DomainName] && !seen[item.DomainName] {
				id := scalarID(item.DomainID)
				if id != "" {
					ids = append(ids, id)
					seen[item.DomainName] = true
				}
			}
		}
		if len(listing.Domains) < 100 {
			break
		}
	}
	if len(seen) != len(wanted) {
		return Result{}, errors.New("one or more configured Ksyun CDN domains were not found")
	}
	data, err := t.call(ctx, http.MethodPost, "ConfigCertificate", "2016-09-01", "/2016-09-01/cert/ConfigCertificate", map[string]any{
		"Enable": "on", "DomainIds": strings.Join(ids, ","), "CertificateName": name,
		"ServerCertificate": string(material.FullChainPEM), "PrivateKey": string(material.PrivateKeyPEM),
	})
	if err != nil {
		return Result{Target: t.Kind(), Written: true}, err
	}
	var response struct {
		CertificateID json.RawMessage `json:"CertificateId"`
	}
	_ = json.Unmarshal(data, &response)
	return Result{Target: t.Kind(), Location: scalarID(response.CertificateID), Written: true}, nil
}

func (t *Ksyun) call(ctx context.Context, method, action, version, path string, params map[string]any) (json.RawMessage, error) {
	var body []byte
	query := url.Values{}
	if method == http.MethodGet {
		for key, value := range params {
			query.Set(key, fmt.Sprint(value))
		}
	} else if len(params) > 0 {
		var err error
		body, err = json.Marshal(params)
		if err != nil {
			return nil, errors.New("encode Ksyun request failed")
		}
	}
	parsed, err := url.Parse(t.endpoint)
	if err != nil {
		return nil, errors.New("invalid Ksyun endpoint")
	}
	date := time.Now().UTC().Format("20060102T150405Z")
	headers := map[string]string{"Host": parsed.Host, "X-Amz-Date": date, "X-Version": version, "X-Action": action}
	canonicalNames := []string{"host", "x-action", "x-amz-date", "x-version"}
	canonicalHeaders := "host:" + parsed.Host + "\n" + "x-action:" + action + "\n" + "x-amz-date:" + date + "\n" + "x-version:" + version + "\n"
	signedNames := strings.Join(canonicalNames, ";")
	canonicalQuery := ""
	if len(query) > 0 {
		keys := make([]string, 0, len(query))
		for key := range query {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, key := range keys {
			parts = append(parts, ksyunEscape(key)+"="+ksyunEscape(query.Get(key)))
		}
		canonicalQuery = strings.Join(parts, "&")
	}
	payloadHash := sha256.Sum256(body)
	canonical := method + "\n" + path + "\n" + canonicalQuery + "\n" + canonicalHeaders + "\n" + signedNames + "\n" + hex.EncodeToString(payloadHash[:])
	canonicalHash := sha256.Sum256([]byte(canonical))
	shortDate := date[:8]
	scope := shortDate + "/cn-shanghai-2/cdn/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + date + "\n" + scope + "\n" + hex.EncodeToString(canonicalHash[:])
	kDate := ksyunHMAC([]byte("AWS4"+t.secret), shortDate)
	kRegion := ksyunHMAC(kDate, "cn-shanghai-2")
	kService := ksyunHMAC(kRegion, "cdn")
	kSigning := ksyunHMAC(kService, "aws4_request")
	signature := hex.EncodeToString(ksyunHMAC(kSigning, stringToSign))
	headers["Authorization"] = "AWS4-HMAC-SHA256 Credential=" + t.keyID + "/" + scope + ", SignedHeaders=" + signedNames + ", Signature=" + signature
	headers["Accept"] = "application/json"
	if len(body) > 0 {
		headers["Content-Type"] = "application/json"
	}
	endpoint := t.endpoint + path
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	status, content, err := request(ctx, t.client, method, endpoint, headers, body)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("Ksyun API returned HTTP %d", status)
	}
	if !json.Valid(content) {
		return nil, requestOutcomeError(t.Kind(), method, "invalid Ksyun API response")
	}
	return content, nil
}

func ksyunHMAC(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func ksyunEscape(value string) string {
	return strings.ReplaceAll(url.QueryEscape(value), "+", "%20")
}

var _ Target = (*Ksyun)(nil)
