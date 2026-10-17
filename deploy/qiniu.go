package deploy

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Qiniu struct {
	accessKey      string
	secretKey      string
	product        string
	domains        []string
	piliHub        string
	cleanupExpired bool
	client         *http.Client
}

func init() {
	register("qiniu", func(config Config) (Target, error) {
		accessKey, secretKey := strings.TrimSpace(config.Values["AccessKey"]), config.Values["SecretKey"]
		product := strings.TrimSpace(config.Values["product"])
		domains := splitList(config.Values["domain"])
		if accessKey == "" || secretKey == "" || len(domains) == 0 {
			return nil, errors.New("Qiniu access keys and domains are required")
		}
		if product != "upload" && product != "cdn" && product != "oss" && product != "pili" {
			return nil, errors.New("unknown Qiniu deployment product")
		}
		if product == "pili" && config.Values["pili_hub"] == "" {
			return nil, errors.New("Qiniu Pili hub is required")
		}
		return &Qiniu{accessKey: accessKey, secretKey: secretKey, product: product, domains: domains,
			piliHub: config.Values["pili_hub"], cleanupExpired: config.Values["cleanup_expired"] == "true", client: client(config)}, nil
	})
}

func (t *Qiniu) Kind() string { return "qiniu" }

func (t *Qiniu) Check(ctx context.Context) error {
	_, err := t.call(ctx, false, http.MethodGet, "/sslcert", nil, nil)
	return err
}

func (t *Qiniu) Deploy(ctx context.Context, material Material) (Result, error) {
	leaf, err := certificate(material)
	if err != nil {
		return Result{}, err
	}
	name := fmt.Sprintf("%s-%d", strings.TrimPrefix(leaf.Subject.CommonName, "*."), leaf.NotBefore.Unix())
	id, uploaded, err := t.certificateID(ctx, material, leaf.Subject.CommonName, name)
	if err != nil {
		return Result{Target: t.Kind(), Written: uploaded}, err
	}
	result := Result{Target: t.Kind(), Location: id, Written: uploaded}
	if t.product == "upload" {
		return result, nil
	}
	for _, domain := range t.domains {
		switch t.product {
		case "cdn":
			err = t.deployCDN(ctx, domain, id)
		case "oss":
			_, err = t.call(ctx, false, http.MethodPost, "/cert/bind", nil, map[string]string{"certid": id, "domain": domain})
		case "pili":
			_, err = t.call(ctx, true, http.MethodPost, "/v2/hubs/"+url.PathEscape(t.piliHub)+"/domains/"+url.PathEscape(domain)+"/cert", nil,
				map[string]string{"CertName": name})
		}
		if err != nil {
			return result, err
		}
		result.Written = true
	}
	return result, nil
}

func (t *Qiniu) deployCDN(ctx context.Context, domain, id string) error {
	path := "/domain/" + url.PathEscape(domain)
	data, err := t.call(ctx, false, http.MethodGet, path, nil, nil)
	if err != nil {
		return err
	}
	var current struct {
		HTTPS struct {
			CertID      string          `json:"certId"`
			ForceHTTPS  json.RawMessage `json:"forceHttps"`
			HTTP2Enable json.RawMessage `json:"http2Enable"`
		} `json:"https"`
	}
	if err := json.Unmarshal(data, &current); err != nil {
		return errors.New("invalid Qiniu CDN domain response")
	}
	if current.HTTPS.CertID == id {
		return nil
	}
	if current.HTTPS.CertID == "" {
		_, err = t.call(ctx, false, http.MethodPut, path+"/sslize", nil, map[string]string{"certid": id})
	} else {
		payload := map[string]any{"certid": id, "forceHttps": current.HTTPS.ForceHTTPS, "http2Enable": current.HTTPS.HTTP2Enable}
		_, err = t.call(ctx, false, http.MethodPut, path+"/httpsconf", nil, payload)
	}
	return err
}

func (t *Qiniu) certificateID(ctx context.Context, material Material, commonName, name string) (string, bool, error) {
	marker := ""
	seen := map[string]bool{}
	for {
		data, err := t.call(ctx, false, http.MethodGet, "/sslcert", url.Values{"marker": {marker}, "limit": {"100"}}, nil)
		if err != nil {
			return "", false, err
		}
		var list struct {
			Marker string `json:"marker"`
			Certs  []struct {
				Name     string `json:"name"`
				CertID   string `json:"certid"`
				NotAfter int64  `json:"not_after"`
			} `json:"certs"`
		}
		if err := json.Unmarshal(data, &list); err != nil {
			return "", false, errors.New("invalid Qiniu certificate list")
		}
		for _, item := range list.Certs {
			if item.Name == name && item.CertID != "" {
				return item.CertID, false, nil
			}
			if t.cleanupExpired && item.NotAfter > 0 && item.NotAfter < time.Now().Unix() && item.CertID != "" {
				_, _ = t.call(ctx, false, http.MethodDelete, "/sslcert/"+url.PathEscape(item.CertID), nil, nil)
			}
		}
		if list.Marker == "" || len(list.Certs) == 0 {
			break
		}
		if seen[list.Marker] {
			return "", false, errors.New("Qiniu certificate pagination repeated marker")
		}
		seen[list.Marker] = true
		marker = list.Marker
	}
	data, err := t.call(ctx, false, http.MethodPost, "/sslcert", nil, map[string]string{
		"name": name, "common_name": commonName, "pri": string(material.PrivateKeyPEM), "ca": string(material.FullChainPEM),
	})
	if err != nil {
		return "", false, err
	}
	var created struct {
		CertID string `json:"certID"`
	}
	if json.Unmarshal(data, &created) != nil || created.CertID == "" {
		return "", true, errors.New("Qiniu uploaded certificate but did not return ID")
	}
	if err := waitContext(ctx, 500*time.Millisecond); err != nil {
		return created.CertID, true, err
	}
	return created.CertID, true, nil
}

func (t *Qiniu) call(ctx context.Context, pili bool, method, path string, query url.Values, payload any) (json.RawMessage, error) {
	host, authorization := "https://api.qiniu.com", "QBox "
	if pili {
		host, authorization = "https://pili.qiniuapi.com", "Qiniu "
	}
	var body []byte
	if payload != nil {
		var err error
		body, err = json.Marshal(payload)
		if err != nil {
			return nil, errors.New("encode Qiniu request failed")
		}
	}
	queryString := ""
	if len(query) > 0 {
		queryString = "?" + query.Encode()
	}
	toSign := path + queryString + "\n"
	if pili {
		toSign = method + " " + path + queryString + "\nHost: pili.qiniuapi.com"
		if len(body) > 0 {
			toSign += "\nContent-Type: application/json"
		}
		toSign += "\n\n" + string(body)
	}
	mac := hmac.New(sha1.New, []byte(t.secretKey))
	_, _ = mac.Write([]byte(toSign))
	signature := base64.URLEncoding.EncodeToString(mac.Sum(nil))
	headers := map[string]string{"Authorization": authorization + t.accessKey + ":" + signature}
	if len(body) > 0 {
		headers["Content-Type"] = "application/json"
	}
	status, content, err := request(ctx, t.client, method, host+path+queryString, headers, body)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("Qiniu API returned HTTP %d", status)
	}
	if len(content) == 0 {
		return json.RawMessage(`true`), nil
	}
	if !json.Valid(content) {
		return nil, requestOutcomeError(t.Kind(), method, "invalid Qiniu API response")
	}
	return content, nil
}

var _ Target = (*Qiniu)(nil)
