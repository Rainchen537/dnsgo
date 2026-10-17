package deploy

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rainchen537/dnsgo"
)

type Wangsu struct {
	username string
	apiKey   string
	spKey    string
	product  string
	certID   string
	domains  []string
	domain   string
	client   *http.Client
}

type wangsuResponse struct {
	status   int
	body     []byte
	location string
}

func init() {
	register("wangsu", func(config Config) (Target, error) {
		username, apiKey := strings.TrimSpace(config.Values["username"]), config.Values["apiKey"]
		if username == "" || apiKey == "" {
			return nil, errors.New("Wangsu username and API key are required")
		}
		product := strings.TrimSpace(config.Values["product"])
		if product != "cdn" && product != "cdnpro" && product != "certificate" && product != "cdnpro_certificate" {
			return nil, errors.New("unknown Wangsu deployment product")
		}
		target := &Wangsu{username: username, apiKey: apiKey, spKey: config.Values["spKey"], product: product,
			certID: strings.TrimSpace(config.Values["cert_id"]), domains: splitList(config.Values["domains"]),
			domain: strings.TrimSpace(config.Values["domain"]), client: client(config)}
		if product == "cdn" && len(target.domains) == 0 || product == "cdnpro" && target.domain == "" {
			return nil, errors.New("Wangsu CDN deployment domains are required")
		}
		if (product == "certificate" || product == "cdnpro_certificate") && target.certID == "" {
			return nil, errors.New("Wangsu certificate ID is required")
		}
		return target, nil
	})
}

func (t *Wangsu) Kind() string { return "wangsu" }

func (t *Wangsu) Check(ctx context.Context) error {
	_, err := t.call(ctx, http.MethodGet, "/api/ssl/certificate", nil, nil, "", nil)
	return err
}

func (t *Wangsu) Deploy(ctx context.Context, material Material) (Result, error) {
	leaf, err := certificate(material)
	if err != nil {
		return Result{}, err
	}
	name := fmt.Sprintf("%s-%d", strings.TrimPrefix(leaf.Subject.CommonName, "*."), leaf.NotBefore.Unix())
	serial := strings.ToLower(leaf.SerialNumber.Text(16))
	switch t.product {
	case "cdnpro":
		return t.deployCDNPro(ctx, material, name)
	case "cdnpro_certificate":
		return t.deployCDNProCertificate(ctx, material, name)
	case "cdn", "certificate":
		id, written, err := t.certificateID(ctx, material, name, serial, t.product == "certificate")
		result := Result{Target: t.Kind(), Location: id, Written: written}
		if err != nil {
			return result, err
		}
		if t.product == "certificate" {
			return result, nil
		}
		_, err = t.call(ctx, http.MethodPut, "/api/config/certificate/batch", map[string]any{
			"certificateId": id, "domainNames": t.domains,
		}, nil, "", nil)
		if err != nil {
			return result, err
		}
		result.Written = true
		return result, nil
	}
	return Result{}, errors.New("unsupported Wangsu product")
}

func (t *Wangsu) certificateID(ctx context.Context, material Material, name, serial string, overwrite bool) (string, bool, error) {
	id := t.certID
	if id != "" {
		response, err := t.call(ctx, http.MethodGet, "/api/certificate/"+url.PathEscape(id), nil, nil, "", nil)
		if err != nil {
			return id, false, err
		}
		var current struct {
			Message string `json:"message"`
			Data    struct {
				Name   string `json:"name"`
				Serial string `json:"serial"`
			} `json:"data"`
		}
		if json.Unmarshal(response.body, &current) == nil && current.Message == "success" && current.Data.Name == name && strings.EqualFold(current.Data.Serial, serial) {
			return id, false, nil
		}
	} else if overwrite {
		return "", false, errors.New("Wangsu certificate ID is required for overwrite")
	}
	if overwrite {
		_, err := t.call(ctx, http.MethodPut, "/api/certificate/"+url.PathEscape(id), map[string]string{
			"name": name, "certificate": string(material.FullChainPEM), "privateKey": string(material.PrivateKeyPEM),
		}, nil, "", nil)
		if err != nil {
			return id, false, err
		}
		return id, true, nil
	}
	response, err := t.call(ctx, http.MethodGet, "/api/ssl/certificate", nil, nil, "", nil)
	if err != nil {
		return id, false, err
	}
	var list struct {
		Certificates []struct {
			ID     json.RawMessage `json:"certificate-id"`
			Serial string          `json:"certificate-serial"`
			Name   string          `json:"name"`
		} `json:"ssl-certificate"`
	}
	if err := json.Unmarshal(response.body, &list); err != nil {
		return id, false, errors.New("invalid Wangsu certificate list")
	}
	written := false
	for _, item := range list.Certificates {
		itemID := scalarID(item.ID)
		if itemID == "" {
			continue
		}
		if strings.EqualFold(item.Serial, serial) {
			_, err := t.call(ctx, http.MethodPut, "/api/certificate/"+url.PathEscape(itemID), map[string]string{"name": name}, nil, "", nil)
			if err != nil {
				return itemID, written, err
			}
			return itemID, true, nil
		}
		if item.Name == name {
			_, err := t.call(ctx, http.MethodPut, "/api/certificate/"+url.PathEscape(itemID), map[string]string{"name": name + "-bak"}, nil, "", nil)
			if err != nil {
				return id, written, err
			}
			written = true
		}
	}
	created, err := t.call(ctx, http.MethodPost, "/api/certificate", map[string]string{
		"name": name, "certificate": string(material.FullChainPEM), "privateKey": string(material.PrivateKeyPEM),
	}, nil, "", nil)
	if err != nil {
		return id, written, err
	}
	id = wangsuLocationID(created.location)
	if id == "" {
		return "", true, errors.New("Wangsu certificate uploaded but no ID was returned")
	}
	return id, true, nil
}

func wangsuLocationID(location string) string {
	parsed, err := url.Parse(location)
	if err != nil {
		return ""
	}
	path := strings.TrimRight(parsed.Path, "/")
	index := strings.LastIndexByte(path, '/')
	if index < 0 || index == len(path)-1 {
		return ""
	}
	return path[index+1:]
}

func (t *Wangsu) call(ctx context.Context, method, path string, payload any, form url.Values, date string, extra map[string]string) (wangsuResponse, error) {
	if date == "" {
		date = time.Now().UTC().Format(http.TimeFormat)
	}
	mac := hmac.New(sha1.New, []byte(t.apiKey))
	_, _ = mac.Write([]byte(date))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	headers := map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(t.username+":"+signature)),
		"Date": date, "Accept": "application/json", "Connection": "close"}
	for key, value := range extra {
		headers[key] = value
	}
	var body []byte
	if payload != nil {
		var err error
		body, err = json.Marshal(payload)
		if err != nil {
			return wangsuResponse{}, errors.New("encode Wangsu request failed")
		}
		headers["Content-Type"] = "application/json"
	}
	if form != nil {
		body = []byte(form.Encode())
		headers["Content-Type"] = "application/x-www-form-urlencoded"
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://open.chinanetcenter.com"+path, bytes.NewReader(body))
	if err != nil {
		return wangsuResponse{}, errors.New("invalid Wangsu request")
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	httpClient := *t.client
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := httpClient.Do(req)
	if err != nil {
		code := dnsgo.CodeResultUnknown
		if method == http.MethodGet || method == http.MethodHead {
			code = dnsgo.CodeTransport
		}
		return wangsuResponse{}, &dnsgo.Error{Provider: "wangsu", Operation: method, Code: code, Message: "request failed"}
	}
	defer response.Body.Close()
	content, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		code := dnsgo.CodeResultUnknown
		if method == http.MethodGet || method == http.MethodHead {
			code = dnsgo.CodeTransport
		}
		return wangsuResponse{}, &dnsgo.Error{Provider: "wangsu", Operation: method, Code: code, Message: "response read failed"}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		if (response.StatusCode == http.StatusRequestTimeout || response.StatusCode >= 500) && method != http.MethodGet && method != http.MethodHead {
			return wangsuResponse{}, &dnsgo.Error{Provider: "wangsu", Operation: method,
				Code: dnsgo.CodeResultUnknown, Message: "server error after write request; inspect target before retrying"}
		}
		return wangsuResponse{}, fmt.Errorf("Wangsu API returned HTTP %d", response.StatusCode)
	}
	return wangsuResponse{status: response.StatusCode, body: content, location: response.Header.Get("Location")}, nil
}

var _ Target = (*Wangsu)(nil)
