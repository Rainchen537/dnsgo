package deploy

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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

type CTYun struct {
	keyID   string
	secret  string
	product string
	domains []string
	region  string
	client  *http.Client
}

type ctyunAPIError struct {
	status  int
	message string
}

func (e *ctyunAPIError) Error() string {
	return fmt.Sprintf("CTYun API rejected request (status %d)", e.status)
}

func init() {
	register("ctyun", func(config Config) (Target, error) {
		keyID, secret := strings.TrimSpace(config.Values["AccessKeyId"]), config.Values["SecretAccessKey"]
		product := strings.TrimSpace(config.Values["product"])
		if keyID == "" || secret == "" {
			return nil, errors.New("CTYun access keys are required")
		}
		if product != "cdn" && product != "icdn" && product != "accessone" && product != "cf" {
			return nil, errors.New("unknown CTYun deployment product")
		}
		domains := splitList(config.Values["domain"])
		if len(domains) == 0 {
			return nil, errors.New("CTYun deployment domains are required")
		}
		if product == "cf" && config.Values["region_id"] == "" {
			return nil, errors.New("CTYun Function Compute region is required")
		}
		return &CTYun{keyID: keyID, secret: secret, product: product, domains: domains, region: config.Values["region_id"], client: client(config)}, nil
	})
}

func (t *CTYun) Kind() string { return "ctyun" }

func (t *CTYun) Check(ctx context.Context) error {
	_, err := t.call(ctx, "ctcdn-global.ctapi.ctyun.cn", http.MethodGet, "/v1/cert/query-cert-list", nil, nil, nil)
	return err
}

func (t *CTYun) Deploy(ctx context.Context, material Material) (Result, error) {
	leaf, err := certificate(material)
	if err != nil {
		return Result{}, err
	}
	name := fmt.Sprintf("%s-%d", strings.TrimPrefix(leaf.Subject.CommonName, "*."), leaf.NotBefore.Unix())
	if t.product == "cf" {
		return t.deployCF(ctx, material, name)
	}
	host, uploadPath := "ctcdn-global.ctapi.ctyun.cn", "/v1/cert/creat-cert"
	switch t.product {
	case "icdn":
		host = "icdn-global.ctapi.ctyun.cn"
	case "accessone":
		host, uploadPath = "accessone-global.ctapi.ctyun.cn", "/ctapi/v1/accessone/cert/create"
	}
	result := Result{Target: t.Kind()}
	_, err = t.call(ctx, host, http.MethodPost, uploadPath, nil, map[string]string{
		"name": name, "key": string(material.PrivateKeyPEM), "certs": string(material.FullChainPEM),
	}, nil)
	if err != nil {
		var apiError *ctyunAPIError
		if !errors.As(err, &apiError) || !strings.Contains(apiError.message, "已存在重名的证书") {
			return result, err
		}
	} else {
		result.Written = true
	}
	for _, domain := range t.domains {
		if t.product == "accessone" {
			err = t.bindAccessOne(ctx, host, domain, name)
		} else {
			_, err = t.call(ctx, host, http.MethodPost, "/v1/domain/update-domain", nil,
				map[string]string{"domain": domain, "https_status": "on", "cert_name": name}, nil)
		}
		if err != nil {
			var apiError *ctyunAPIError
			if !errors.As(err, &apiError) || !strings.Contains(apiError.message, "请求已提交，请勿重复操作") {
				return result, err
			}
		}
		result.Written = true
		if result.Location != "" {
			result.Location += ","
		}
		result.Location += domain
	}
	return result, nil
}

func (t *CTYun) bindAccessOne(ctx context.Context, host, domain, name string) error {
	data, err := t.call(ctx, host, http.MethodPost, "/ctapi/v1/accessone/domain/config", nil,
		map[string]string{"domain": domain, "product_code": "020"}, nil)
	if err != nil {
		return err
	}
	var current map[string]any
	if err := json.Unmarshal(data, &current); err != nil {
		return errors.New("invalid CTYun AccessOne configuration")
	}
	if current["https_status"] == "on" && current["cert_name"] == name {
		return nil
	}
	current["https_status"], current["cert_name"] = "on", name
	for _, key := range []string{"status", "area_scope", "cname", "insert_date", "status_date", "record_status", "record_num",
		"customer_name", "outlink_replace_filter", "website_ipv6_access_mark", "websocket_speed", "dynamic_config", "dynamic_ability"} {
		delete(current, key)
	}
	for key, value := range current {
		if entries, ok := value.([]any); ok && len(entries) == 0 {
			delete(current, key)
		}
	}
	if origins, ok := current["origin"].([]any); ok {
		for _, entry := range origins {
			if origin, ok := entry.(map[string]any); ok && origin["weight"] != nil {
				origin["weight"] = fmt.Sprint(origin["weight"])
			}
		}
	}
	_, err = t.call(ctx, host, http.MethodPost, "/ctapi/v1/scdn/domain/modify_config", nil, current, nil)
	return err
}

func (t *CTYun) deployCF(ctx context.Context, material Material, name string) (Result, error) {
	host := "cf-global.ctapi.ctyun.cn"
	result := Result{Target: t.Kind()}
	for _, domain := range t.domains {
		path := "/openapi/v1/domains/customdomains/" + url.PathEscape(domain)
		data, err := t.call(ctx, host, http.MethodGet, path, nil, nil, map[string]string{"regionId": t.region})
		if err != nil {
			return result, err
		}
		var current struct {
			Description string `json:"description"`
			Protocol    string `json:"protocol"`
			CertConfig  struct {
				Certificate string `json:"certificate"`
			} `json:"certConfig"`
			AuthConfig  json.RawMessage `json:"authConfig"`
			RouteConfig json.RawMessage `json:"routeConfig"`
		}
		if err := json.Unmarshal(data, &current); err != nil {
			return result, errors.New("invalid CTYun Function Compute domain configuration")
		}
		if strings.TrimSpace(current.CertConfig.Certificate) == strings.TrimSpace(string(material.FullChainPEM)) {
			continue
		}
		protocol := current.Protocol
		if protocol == "HTTP" {
			protocol = "HTTP,HTTPS"
		}
		certName := "cert" + name[strings.LastIndex(name, "-")+1:]
		payload := map[string]any{"domainName": domain, "description": current.Description, "protocol": protocol,
			"certConfig": map[string]string{"certName": certName, "certificate": string(material.FullChainPEM), "privateKey": string(material.PrivateKeyPEM)},
			"authConfig": current.AuthConfig, "routeConfig": current.RouteConfig}
		_, err = t.call(ctx, host, http.MethodPut, path, nil, payload, map[string]string{"regionId": t.region})
		if err != nil {
			var apiError *ctyunAPIError
			if !errors.As(err, &apiError) || !strings.Contains(apiError.message, "请求已提交，请勿重复操作") {
				return result, err
			}
		}
		result.Written = true
		if result.Location != "" {
			result.Location += ","
		}
		result.Location += domain
	}
	return result, nil
}

func (t *CTYun) call(ctx context.Context, host, method, path string, query url.Values, payload any, extra map[string]string) (json.RawMessage, error) {
	var body []byte
	if payload != nil {
		var err error
		body, err = json.Marshal(payload)
		if err != nil {
			return nil, errors.New("encode CTYun request failed")
		}
	}
	date := time.Now().UTC().Format("20060102T150405Z")
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, errors.New("CTYun request ID generation failed")
	}
	headers := map[string]string{"Host": host, "Eop-date": date, "ctyun-eop-request-id": hex.EncodeToString(random[:])}
	if len(body) > 0 {
		headers["Content-Type"] = "application/json"
	}
	for key, value := range extra {
		headers[key] = value
	}
	names := make([]string, 0, len(headers))
	canonical := map[string]string{}
	for key, value := range headers {
		low := strings.ToLower(key)
		names = append(names, low)
		canonical[low] = strings.TrimSpace(value)
	}
	sort.Strings(names)
	var canonicalHeaders strings.Builder
	for _, name := range names {
		canonicalHeaders.WriteString(name + ":" + canonical[name] + "\n")
	}
	queryString := ""
	if len(query) > 0 {
		queryString = strings.ReplaceAll(query.Encode(), "+", "%20")
	}
	hash := sha256.Sum256(body)
	toSign := canonicalHeaders.String() + "\n" + queryString + "\n" + hex.EncodeToString(hash[:])
	key := ksyunHMAC([]byte(t.secret), date)
	key = ksyunHMAC(key, t.keyID)
	key = ksyunHMAC(key, date[:8])
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(toSign))
	headers["Eop-Authorization"] = t.keyID + " Headers=" + strings.Join(names, ";") + " Signature=" + base64.StdEncoding.EncodeToString(mac.Sum(nil))
	endpoint := "https://" + host + path
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	status, content, err := request(ctx, t.client, method, endpoint, headers, body)
	if err != nil {
		return nil, err
	}
	var response struct {
		StatusCode   int             `json:"statusCode"`
		ReturnObj    json.RawMessage `json:"returnObj"`
		ErrorMessage string          `json:"errorMessage"`
		Message      string          `json:"message"`
	}
	if err := json.Unmarshal(content, &response); err != nil {
		if path == "/ctapi/v1/accessone/domain/config" {
			return nil, errors.New("invalid CTYun AccessOne configuration response")
		}
		return nil, requestOutcomeError(t.Kind(), method, "invalid CTYun API response")
	}
	if status < 200 || status >= 300 || response.StatusCode != 100000 && !(host == "cf-global.ctapi.ctyun.cn" && response.StatusCode == 0) {
		message := response.ErrorMessage
		if message == "" {
			message = response.Message
		}
		return nil, &ctyunAPIError{status: response.StatusCode, message: message}
	}
	if len(response.ReturnObj) == 0 {
		return json.RawMessage(`true`), nil
	}
	return response.ReturnObj, nil
}

var _ Target = (*CTYun)(nil)
