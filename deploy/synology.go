package deploy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Synology struct {
	endpoint string
	username string
	password string
	version  string
	desc     string
	client   *http.Client
}

func init() {
	register("synology", func(config Config) (Target, error) {
		if config.Endpoint == "" {
			config.Endpoint = config.Values["url"]
		}
		endpoint, err := targetEndpoint(config, "")
		if err != nil {
			return nil, err
		}
		username, password := strings.TrimSpace(config.Values["username"]), config.Values["password"]
		if username == "" || password == "" {
			return nil, errors.New("Synology username and password are required")
		}
		return &Synology{endpoint: endpoint, username: username, password: password,
			version: config.Values["version"], desc: config.Values["desc"], client: client(config)}, nil
	})
}

func (t *Synology) Kind() string { return "synology" }

func (t *Synology) Check(ctx context.Context) error { _, _, err := t.login(ctx); return err }

func (t *Synology) Deploy(ctx context.Context, material Material) (Result, error) {
	leaf, err := certificate(material)
	if err != nil {
		return Result{}, err
	}
	sid, token, err := t.login(ctx)
	if err != nil {
		return Result{}, err
	}
	params := url.Values{"api": {"SYNO.Core.Certificate.CRT"}, "version": {"1"}, "method": {"list"}, "_sid": {sid}, "SynoToken": {token}}
	status, content, err := request(ctx, t.client, http.MethodGet, t.endpoint+"/webapi/entry.cgi?"+params.Encode(), nil, nil)
	if err != nil {
		return Result{}, err
	}
	var listing struct {
		Success bool `json:"success"`
		Data    struct {
			Certificates []struct {
				ID        json.RawMessage `json:"id"`
				Desc      string          `json:"desc"`
				ValidFrom string          `json:"valid_from"`
				Subject   struct {
					CommonName string `json:"common_name"`
				} `json:"subject"`
			} `json:"certificates"`
		} `json:"data"`
	}
	if err := json.Unmarshal(content, &listing); err != nil || status != http.StatusOK || !listing.Success {
		return Result{}, errors.New("Synology certificate list failed")
	}
	for _, item := range listing.Data.Certificates {
		if item.Subject.CommonName != leaf.Subject.CommonName && (t.desc == "" || item.Desc != t.desc) {
			continue
		}
		id := scalarID(item.ID)
		if id == "" {
			return Result{}, errors.New("Synology certificate ID is missing")
		}
		if synologySameStart(item.ValidFrom, leaf.NotBefore) {
			return Result{Target: t.Kind(), Location: id, Written: false}, nil
		}
		return t.importCertificate(ctx, sid, token, id, material)
	}
	return t.importCertificate(ctx, sid, token, "", material)
}

func synologySameStart(value string, expected time.Time) bool {
	for _, layout := range []string{"Jan 2 15:04:05 2006 MST", "Jan 02 15:04:05 2006 MST", "2006-01-02 15:04:05"} {
		parsed, err := time.Parse(layout, value)
		if err == nil && parsed.Unix() == expected.Unix() {
			return true
		}
	}
	return false
}

func (t *Synology) importCertificate(ctx context.Context, sid, token, id string, material Material) (Result, error) {
	params := url.Values{"api": {"SYNO.Core.Certificate"}, "version": {"1"}, "method": {"import"}, "_sid": {sid}, "SynoToken": {token}}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	keyFile, err := writer.CreateFormFile("key", "key.pem")
	if err != nil {
		return Result{}, errors.New("prepare Synology key upload failed")
	}
	if _, err := keyFile.Write(material.PrivateKeyPEM); err != nil {
		return Result{}, errors.New("prepare Synology key upload failed")
	}
	certFile, err := writer.CreateFormFile("cert", "cert.pem")
	if err != nil {
		return Result{}, errors.New("prepare Synology certificate upload failed")
	}
	if _, err := certFile.Write(material.FullChainPEM); err != nil {
		return Result{}, errors.New("prepare Synology certificate upload failed")
	}
	if err := writer.WriteField("id", id); err != nil {
		return Result{}, err
	}
	if err := writer.WriteField("desc", t.desc); err != nil {
		return Result{}, err
	}
	if err := writer.Close(); err != nil {
		return Result{}, err
	}
	status, content, err := request(ctx, t.client, http.MethodPost, t.endpoint+"/webapi/entry.cgi?"+params.Encode(),
		map[string]string{"Content-Type": writer.FormDataContentType()}, body.Bytes())
	if err != nil {
		return Result{Target: t.Kind(), Location: id, Written: true}, err
	}
	var response struct {
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(content, &response); err != nil || status != http.StatusOK || !response.Success {
		return Result{Target: t.Kind(), Location: id, Written: status >= 200 && status < 300},
			fmt.Errorf("Synology certificate import failed (HTTP %d)", status)
	}
	location := id
	if location == "" {
		location = "new certificate"
	}
	return Result{Target: t.Kind(), Location: location, Written: true}, nil
}

func (t *Synology) login(ctx context.Context) (sid, token string, err error) {
	path := "/webapi/entry.cgi"
	if t.version == "1" {
		path = "/webapi/auth.cgi"
	}
	params := url.Values{"api": {"SYNO.API.Auth"}, "version": {"6"}, "method": {"login"}, "session": {"webui"},
		"account": {t.username}, "passwd": {t.password}, "format": {"sid"}, "enable_syno_token": {"yes"}}
	status, content, err := request(ctx, t.client, http.MethodPost, t.endpoint+path,
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, []byte(params.Encode()))
	if err != nil {
		return "", "", err
	}
	var response struct {
		Success bool `json:"success"`
		Data    struct {
			SID   string `json:"sid"`
			Token string `json:"synotoken"`
		} `json:"data"`
	}
	if json.Unmarshal(content, &response) != nil || status != http.StatusOK || !response.Success || response.Data.SID == "" {
		return "", "", fmt.Errorf("Synology login failed (HTTP %d)", status)
	}
	return response.Data.SID, response.Data.Token, nil
}

var _ Target = (*Synology)(nil)
