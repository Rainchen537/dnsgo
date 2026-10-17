package deploy

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rainchen537/dnsgo"
)

type BTPanel struct {
	kind     string
	endpoint string
	key      string
	mode     string
	iis      bool
	sites    []string
	client   *http.Client
}

func init() {
	for _, name := range []string{"btpanel", "btwin"} {
		kind := name
		register(kind, func(config Config) (Target, error) {
			if config.Endpoint == "" {
				config.Endpoint = config.Values["url"]
			}
			endpoint, err := targetEndpoint(config, "")
			if err != nil {
				return nil, err
			}
			key := strings.TrimSpace(config.Values["key"])
			if key == "" {
				return nil, errors.New("BT panel API key is required")
			}
			mode := config.Values["type"]
			sites := splitList(config.Values["sites"])
			if mode != "1" && len(sites) == 0 {
				return nil, errors.New("BT panel site names are required")
			}
			return &BTPanel{kind: kind, endpoint: endpoint, key: key, mode: mode,
				iis: kind == "btwin" && mode == "0" && config.Values["is_iis"] == "1", sites: sites, client: client(config)}, nil
		})
	}
}

func (t *BTPanel) Kind() string { return t.kind }

func (t *BTPanel) Check(ctx context.Context) error {
	path := "/config?action=get_config"
	if t.kind == "btwin" {
		path = "/config/get_config"
	}
	data, err := t.form(ctx, path, nil)
	if err != nil {
		return err
	}
	if t.kind == "btwin" {
		var value struct {
			Panel struct {
				Status json.RawMessage `json:"status"`
			} `json:"panel"`
		}
		if json.Unmarshal(data, &value) != nil || !jsonTruthy(value.Panel.Status) {
			return errors.New("BT Windows panel status check failed")
		}
		return nil
	}
	var value struct {
		Status    json.RawMessage `json:"status"`
		SitesPath json.RawMessage `json:"sites_path"`
	}
	if json.Unmarshal(data, &value) != nil || !jsonTruthy(value.Status) && len(value.SitesPath) == 0 {
		return errors.New("BT panel status check failed")
	}
	return nil
}

func (t *BTPanel) Deploy(ctx context.Context, material Material) (Result, error) {
	if _, err := certificate(material); err != nil {
		return Result{}, err
	}
	if t.mode == "1" {
		path := "/config?action=SavePanelSSL"
		params := url.Values{"privateKey": {string(material.PrivateKeyPEM)}, "certPem": {string(material.FullChainPEM)}}
		if t.kind == "btwin" {
			path = "/config/set_panel_ssl"
			params = url.Values{"ssl_key": {string(material.PrivateKeyPEM)}, "ssl_pem": {string(material.FullChainPEM)}}
		}
		if err := t.formOK(ctx, path, params); err != nil {
			return Result{Target: t.Kind(), Location: "panel", Written: true}, err
		}
		return Result{Target: t.Kind(), Location: "panel", Written: true}, nil
	}
	result := Result{Target: t.Kind()}
	pfxPath := ""
	if t.iis {
		pair, _ := tls.X509KeyPair(material.FullChainPEM, material.PrivateKeyPEM)
		var err error
		pfxPath, err = t.uploadWindowsPFX(ctx, pair)
		if err != nil {
			return result, err
		}
		result.Written = true
		result.Location = pfxPath
	}
	failures := 0
	for _, site := range t.sites {
		var err error
		if t.kind == "btwin" {
			if t.iis {
				err = t.winIIS(ctx, site, pfxPath)
			} else {
				err = t.winSite(ctx, site, material)
			}
		} else {
			err = t.unixSite(ctx, site, material)
		}
		if err != nil {
			failures++
			if dnsgo.IsCode(err, dnsgo.CodeResultUnknown) {
				result.Written = true
				return result, err
			}
			continue
		}
		result.Written = true
		if result.Location != "" {
			result.Location += ","
		}
		result.Location += site
	}
	if !result.Written || t.iis && result.Location == pfxPath {
		return result, errors.New("BT panel site deployment failed for every target")
	}
	if failures > 0 {
		return result, fmt.Errorf("BT panel site deployment failed for %d targets", failures)
	}
	return result, nil
}

func (t *BTPanel) unixSite(ctx context.Context, name string, material Material) error {
	var path string
	var values url.Values
	switch t.mode {
	case "4":
		path = "/mod/proxy/com/set_ssl"
		values = url.Values{"site_name": {name}, "key": {string(material.PrivateKeyPEM)}, "csr": {string(material.FullChainPEM)}}
	case "3":
		path = "/mod/docker/com/set_ssl"
		values = url.Values{"site_name": {name}, "key": {string(material.PrivateKeyPEM)}, "csr": {string(material.FullChainPEM)}}
	case "2":
		path = "/plugin?action=a&name=mail_sys&s=set_mail_certificate_multiple"
		values = url.Values{"domain": {name}, "key": {string(material.PrivateKeyPEM)}, "csr": {string(material.FullChainPEM)}, "act": {"add"}}
	default:
		path = "/site?action=SetSSL"
		values = url.Values{"type": {"0"}, "siteName": {name}, "key": {string(material.PrivateKeyPEM)}, "csr": {string(material.FullChainPEM)}}
	}
	return t.formOK(ctx, path, values)
}

func (t *BTPanel) winSite(ctx context.Context, name string, material Material) error {
	data, err := t.form(ctx, "/datalist/get_data_list", url.Values{"table": {"sites"}, "search_type": {"PHP"}, "search": {name}, "p": {"1"}, "limit": {"10"}, "type": {"-1"}})
	if err != nil {
		return err
	}
	var list struct {
		Data []struct {
			ID   json.RawMessage `json:"id"`
			Name string          `json:"name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &list); err != nil {
		return errors.New("invalid BT Windows site list")
	}
	for _, site := range list.Data {
		if site.Name != name {
			continue
		}
		id := scalarID(site.ID)
		if id == "" {
			return errors.New("BT Windows site ID is missing")
		}
		return t.formOK(ctx, "/site/set_site_ssl", url.Values{"siteid": {id}, "status": {"true"}, "sslType": {""},
			"cert": {string(material.FullChainPEM)}, "key": {string(material.PrivateKeyPEM)}})
	}
	return errors.New("BT Windows site was not found")
}

func (t *BTPanel) winIIS(ctx context.Context, domain, path string) error {
	return t.formOK(ctx, "/site/set_site_domain_ssl", url.Values{"domain": {domain}, "path": {path}, "password": {"123456"}})
}

func (t *BTPanel) uploadWindowsPFX(ctx context.Context, pair tls.Certificate) (string, error) {
	data, err := t.form(ctx, "/panel/get_config", nil)
	if err != nil {
		return "", err
	}
	var configuration struct {
		Paths struct {
			Soft string `json:"soft"`
		} `json:"paths"`
		Config struct {
			Webserver string `json:"webserver"`
		} `json:"config"`
	}
	if json.Unmarshal(data, &configuration) != nil || configuration.Paths.Soft == "" || configuration.Config.Webserver != "iis" {
		return "", errors.New("BT Windows panel is not configured for IIS")
	}
	encoded, err := ftpPFX(pair, "123456")
	if err != nil {
		return "", err
	}
	directory := strings.TrimRight(configuration.Paths.Soft, "/") + "/temp/ssl/" + strconv.FormatInt(time.Now().UnixMilli(), 10)
	path := directory + "/cert.pfx"
	fields := map[string]string{"path": directory, "filename": "cert.pfx", "size": strconv.Itoa(len(encoded)), "start": "0", "force": "true"}
	response, err := t.multipart(ctx, "/files/upload", fields, "blob", "cert.pfx", encoded)
	if err != nil {
		return "", err
	}
	if !btStatus(response) {
		return "", &dnsgo.Error{Provider: t.Kind(), Operation: "upload_pfx", Code: dnsgo.CodeResultUnknown,
			Message: "BT Windows PFX upload outcome could not be confirmed"}
	}
	return path, nil
}

func (t *BTPanel) authValues() url.Values {
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	keyHash := md5.Sum([]byte(t.key))
	tokenHash := md5.Sum([]byte(timestamp + hex.EncodeToString(keyHash[:])))
	return url.Values{"request_token": {hex.EncodeToString(tokenHash[:])}, "request_time": {timestamp}}
}

func (t *BTPanel) form(ctx context.Context, path string, values url.Values) ([]byte, error) {
	params := t.authValues()
	for key, list := range values {
		params[key] = append([]string(nil), list...)
	}
	status, content, err := request(ctx, t.client, http.MethodPost, t.endpoint+path, map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, []byte(params.Encode()))
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 || !json.Valid(content) {
		if status >= 200 && status < 300 {
			return nil, &dnsgo.Error{Provider: t.Kind(), Operation: path, Code: dnsgo.CodeResultUnknown,
				Message: "BT panel returned an invalid response after a request"}
		}
		return nil, fmt.Errorf("BT panel API failed (HTTP %d)", status)
	}
	return content, nil
}

func (t *BTPanel) formOK(ctx context.Context, path string, values url.Values) error {
	data, err := t.form(ctx, path, values)
	if err != nil {
		return err
	}
	var response struct {
		Status json.RawMessage `json:"status"`
	}
	if json.Unmarshal(data, &response) != nil || len(response.Status) == 0 {
		return &dnsgo.Error{Provider: t.Kind(), Operation: path, Code: dnsgo.CodeResultUnknown,
			Message: "BT panel certificate update returned no status"}
	}
	if !jsonTruthy(response.Status) {
		return errors.New("BT panel API rejected certificate update")
	}
	return nil
}

func btStatus(data []byte) bool {
	var response struct {
		Status json.RawMessage `json:"status"`
	}
	return json.Unmarshal(data, &response) == nil && jsonTruthy(response.Status)
}

func jsonTruthy(raw json.RawMessage) bool {
	switch strings.TrimSpace(string(raw)) {
	case "true", "1", `"1"`, `"true"`:
		return true
	}
	return false
}

func (t *BTPanel) multipart(ctx context.Context, path string, fields map[string]string, fileField, fileName string, content []byte) ([]byte, error) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for key, list := range t.authValues() {
		fields[key] = list[0]
	}
	for key, value := range fields {
		if err := writer.WriteField(key, value); err != nil {
			return nil, err
		}
	}
	file, err := writer.CreateFormFile(fileField, fileName)
	if err != nil {
		return nil, err
	}
	if _, err := file.Write(content); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	status, response, err := request(ctx, t.client, http.MethodPost, t.endpoint+path, map[string]string{"Content-Type": writer.FormDataContentType()}, body.Bytes())
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 || !json.Valid(response) {
		if status >= 200 && status < 300 {
			return nil, &dnsgo.Error{Provider: t.Kind(), Operation: path, Code: dnsgo.CodeResultUnknown,
				Message: "BT panel upload returned an invalid response"}
		}
		return nil, fmt.Errorf("BT panel multipart API failed (HTTP %d)", status)
	}
	return response, nil
}

var _ Target = (*BTPanel)(nil)
