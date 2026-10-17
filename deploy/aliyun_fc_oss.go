package deploy

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

func (t *Aliyun) deployFC(ctx context.Context, material Material, name string) (Result, error) {
	domains := splitList(t.values["domain"])
	host := strings.TrimPrefix(t.values["fc_cname"], "https://")
	host = strings.TrimRight(host, "/")
	if len(domains) == 0 || host == "" || strings.Contains(host, "/") {
		return Result{}, errors.New("Aliyun FC domains and CNAME host are required")
	}
	version := "2023-03-30"
	if t.product == "fc2" {
		version = "2021-04-06"
	}
	result := Result{Target: t.Kind()}
	for _, domain := range domains {
		path := "/" + version + "/custom-domains/" + domain
		content, err := t.acs3(ctx, host, version, http.MethodGet, "GetCustomDomain", path, nil)
		if err != nil {
			return result, err
		}
		var current struct {
			AuthConfig  json.RawMessage `json:"authConfig"`
			CertConfig  map[string]any  `json:"certConfig"`
			Protocol    string          `json:"protocol"`
			RouteConfig json.RawMessage `json:"routeConfig"`
			TLSConfig   json.RawMessage `json:"tlsConfig"`
			WAFConfig   json.RawMessage `json:"wafConfig"`
		}
		if err := json.Unmarshal(content, &current); err != nil {
			return result, errors.New("invalid Aliyun FC custom domain response")
		}
		if current.CertConfig == nil {
			current.CertConfig = map[string]any{}
		}
		if current.CertConfig["certificate"] == string(material.FullChainPEM) {
			continue
		}
		if current.Protocol == "HTTP" {
			current.Protocol = "HTTP,HTTPS"
		}
		current.CertConfig["certName"], current.CertConfig["certificate"], current.CertConfig["privateKey"] = name, string(material.FullChainPEM), string(material.PrivateKeyPEM)
		payload := map[string]any{"certConfig": current.CertConfig, "protocol": current.Protocol,
			"routeConfig": current.RouteConfig, "tlsConfig": current.TLSConfig, "wafConfig": current.WAFConfig}
		if t.product == "fc" {
			payload["authConfig"] = current.AuthConfig
		}
		if _, err := t.acs3(ctx, host, version, http.MethodPut, "UpdateCustomDomain", path, payload); err != nil {
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

func (t *Aliyun) acs3(ctx context.Context, host, version, method, action, path string, payload any) ([]byte, error) {
	var body []byte
	if payload != nil {
		var err error
		body, err = json.Marshal(payload)
		if err != nil {
			return nil, errors.New("encode Aliyun ACS3 request failed")
		}
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, errors.New("Aliyun ACS3 nonce generation failed")
	}
	digest := sha256.Sum256(body)
	headers := map[string]string{"x-acs-action": action, "x-acs-version": version, "x-acs-signature-nonce": hex.EncodeToString(random[:]),
		"x-acs-date": time.Now().UTC().Format("2006-01-02T15:04:05Z"), "x-acs-content-sha256": hex.EncodeToString(digest[:]), "host": host}
	if len(body) > 0 {
		headers["content-type"] = "application/json; charset=utf-8"
	}
	names := make([]string, 0, len(headers))
	for key := range headers {
		names = append(names, key)
	}
	sort.Strings(names)
	var canonicalHeaders strings.Builder
	for _, key := range names {
		canonicalHeaders.WriteString(key + ":" + strings.TrimSpace(headers[key]) + "\n")
	}
	parts := strings.Split(path, "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	canonicalURI := strings.Join(parts, "/")
	canonical := method + "\n" + canonicalURI + "\n\n" + canonicalHeaders.String() + "\n" + strings.Join(names, ";") + "\n" + hex.EncodeToString(digest[:])
	canonicalHash := sha256.Sum256([]byte(canonical))
	toSign := "ACS3-HMAC-SHA256\n" + hex.EncodeToString(canonicalHash[:])
	mac := hmac.New(sha256.New, []byte(t.secret))
	_, _ = mac.Write([]byte(toSign))
	headers["Authorization"] = "ACS3-HMAC-SHA256 Credential=" + t.keyID + ",SignedHeaders=" + strings.Join(names, ";") + ",Signature=" + hex.EncodeToString(mac.Sum(nil))
	status, content, err := request(ctx, t.client, method, "https://"+host+canonicalURI, headers, body)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("Aliyun FC API returned HTTP %d", status)
	}
	if !json.Valid(content) {
		return nil, requestOutcomeError(t.Kind(), method, "invalid Aliyun FC API response")
	}
	return content, nil
}

func (t *Aliyun) deployOSS(ctx context.Context, id string, result *Result) error {
	domains := splitList(t.values["domain"])
	endpoint := strings.TrimPrefix(t.values["oss_endpoint"], "https://")
	endpoint = strings.TrimRight(endpoint, "/")
	bucket := strings.TrimSpace(t.values["oss_bucket"])
	if len(domains) == 0 || endpoint == "" || strings.Contains(endpoint, "/") || bucket == "" || strings.Contains(bucket, "/") {
		return errors.New("Aliyun OSS domains, endpoint and bucket are required")
	}
	for _, domain := range domains {
		body, err := xml.Marshal(struct {
			XMLName xml.Name `xml:"BucketCnameConfiguration"`
			Cname   struct {
				Domain      string `xml:"Domain"`
				Certificate struct {
					CertID string `xml:"CertId"`
					Force  string `xml:"Force"`
				} `xml:"CertificateConfiguration"`
			} `xml:"Cname"`
		}{Cname: struct {
			Domain      string `xml:"Domain"`
			Certificate struct {
				CertID string `xml:"CertId"`
				Force  string `xml:"Force"`
			} `xml:"CertificateConfiguration"`
		}{
			Domain: domain, Certificate: struct {
				CertID string `xml:"CertId"`
				Force  string `xml:"Force"`
			}{CertID: id + "-cn-hangzhou", Force: "true"},
		}})
		if err != nil {
			return errors.New("encode Aliyun OSS CNAME certificate failed")
		}
		body = append([]byte(xml.Header), body...)
		date := time.Now().UTC().Format(http.TimeFormat)
		toSign := "POST\n\napplication/xml\n" + date + "\n/" + bucket + "/?cname&comp=add"
		mac := hmac.New(sha1.New, []byte(t.secret))
		_, _ = mac.Write([]byte(toSign))
		address := "https://" + bucket + "." + endpoint + "/?cname&comp=add"
		status, _, err := request(ctx, t.client, http.MethodPost, address, map[string]string{
			"Content-Type": "application/xml", "Date": date,
			"Authorization": "OSS " + t.keyID + ":" + base64.StdEncoding.EncodeToString(mac.Sum(nil)),
		}, body)
		if err != nil {
			return err
		}
		if err := expectHTTPStatus(status); err != nil {
			return err
		}
		result.Written = true
	}
	return nil
}
