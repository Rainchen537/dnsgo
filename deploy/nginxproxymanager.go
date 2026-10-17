package deploy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
)

type NginxProxyManager struct {
	endpoint string
	email    string
	password string
	domains  []string
	certID   int64
	hostID   int64
	client   *http.Client
}

type npmHost struct {
	ID            int64    `json:"id"`
	CertificateID int64    `json:"certificate_id"`
	DomainNames   []string `json:"domain_names"`
}

func init() {
	register("nginxproxymanager", func(config Config) (Target, error) {
		if config.Endpoint == "" {
			config.Endpoint = config.Values["url"]
		}
		endpoint, err := targetEndpoint(config, "")
		if err != nil {
			return nil, err
		}
		email, password := strings.TrimSpace(config.Values["email"]), config.Values["password"]
		domains := splitList(config.Values["domainList"])
		if email == "" || password == "" || len(domains) == 0 {
			return nil, errors.New("NPM email, password and deployment domains are required")
		}
		var certID, hostID int64
		if value := strings.TrimSpace(config.Values["id"]); value != "" {
			certID, err = strconv.ParseInt(value, 10, 64)
			if err != nil || certID < 0 {
				return nil, errors.New("NPM certificate ID must be numeric")
			}
		}
		if value := strings.TrimSpace(config.Values["host_id"]); value != "" {
			hostID, err = strconv.ParseInt(value, 10, 64)
			if err != nil || hostID < 0 {
				return nil, errors.New("NPM Proxy Host ID must be numeric")
			}
		}
		return &NginxProxyManager{endpoint: endpoint, email: email, password: password, domains: domains, certID: certID, hostID: hostID, client: client(config)}, nil
	})
}

func (t *NginxProxyManager) Kind() string { return "nginxproxymanager" }

func (t *NginxProxyManager) Check(ctx context.Context) error {
	token, err := t.login(ctx)
	if err != nil {
		return err
	}
	_, err = t.call(ctx, token, http.MethodGet, "/nginx/certificates", nil)
	return err
}

func (t *NginxProxyManager) Deploy(ctx context.Context, material Material) (Result, error) {
	if _, err := certificate(material); err != nil {
		return Result{}, err
	}
	token, err := t.login(ctx)
	if err != nil {
		return Result{}, err
	}
	if t.certID > 0 {
		if err := t.checkCustomCertificate(ctx, token, t.certID); err != nil {
			return Result{}, err
		}
		if err := t.upload(ctx, token, t.certID, material); err != nil {
			return Result{Target: t.Kind(), Location: strconv.FormatInt(t.certID, 10), Written: true}, err
		}
		return Result{Target: t.Kind(), Location: strconv.FormatInt(t.certID, 10), Written: true}, nil
	}
	hosts, err := t.resolveHosts(ctx, token)
	if err != nil {
		return Result{}, err
	}
	if len(hosts) == 0 {
		return Result{}, errors.New("NPM matching Proxy Hosts were not found")
	}
	resolvedID := int64(0)
	for _, host := range hosts {
		if host.CertificateID <= 0 {
			continue
		}
		if err := t.checkCustomCertificate(ctx, token, host.CertificateID); err != nil {
			continue
		}
		if resolvedID == 0 {
			resolvedID = host.CertificateID
		} else if resolvedID != host.CertificateID {
			return Result{}, errors.New("NPM matching Proxy Hosts use different custom certificates")
		}
	}
	result := Result{Target: t.Kind()}
	if resolvedID == 0 {
		data, err := t.call(ctx, token, http.MethodPost, "/nginx/certificates", map[string]string{"provider": "other", "nice_name": t.domains[0]})
		if err != nil {
			return Result{Target: t.Kind(), Written: true}, err
		}
		var created struct {
			ID int64 `json:"id"`
		}
		if json.Unmarshal(data, &created) != nil || created.ID <= 0 {
			return Result{Target: t.Kind(), Written: true}, errors.New("NPM created certificate but did not return ID")
		}
		resolvedID = created.ID
		result.Written = true
	}
	result.Location = strconv.FormatInt(resolvedID, 10)
	if err := t.upload(ctx, token, resolvedID, material); err != nil {
		result.Written = true
		return result, err
	}
	result.Written = true
	for _, host := range hosts {
		if host.CertificateID == resolvedID {
			continue
		}
		if _, err := t.call(ctx, token, http.MethodPut, "/nginx/proxy-hosts/"+strconv.FormatInt(host.ID, 10), map[string]int64{"certificate_id": resolvedID}); err != nil {
			result.Written = true
			return result, err
		}
	}
	return result, nil
}

func (t *NginxProxyManager) login(ctx context.Context) (string, error) {
	data, err := t.call(ctx, "", http.MethodPost, "/tokens", map[string]string{"identity": t.email, "secret": t.password})
	if err != nil {
		return "", err
	}
	var response struct {
		Token       string `json:"token"`
		Requires2FA bool   `json:"requires_2fa"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return "", errors.New("invalid NPM login response")
	}
	if response.Requires2FA {
		return "", errors.New("NPM account requires two-factor authentication")
	}
	if response.Token == "" {
		return "", errors.New("NPM login did not return a token")
	}
	return response.Token, nil
}

func (t *NginxProxyManager) resolveHosts(ctx context.Context, token string) ([]npmHost, error) {
	if t.hostID > 0 {
		host, err := t.getHost(ctx, token, t.hostID)
		if err != nil {
			return nil, err
		}
		return []npmHost{host}, nil
	}
	data, err := t.call(ctx, token, http.MethodGet, "/nginx/proxy-hosts", nil)
	if err != nil {
		return nil, err
	}
	var listing []npmHost
	if err := json.Unmarshal(data, &listing); err != nil {
		return nil, errors.New("invalid NPM Proxy Host list")
	}
	var matched []npmHost
	for _, host := range listing {
		if !t.matchAny(host.DomainNames) {
			continue
		}
		detail, err := t.getHost(ctx, token, host.ID)
		if err != nil {
			return nil, err
		}
		matched = append(matched, detail)
	}
	return matched, nil
}

func (t *NginxProxyManager) matchAny(hostDomains []string) bool {
	for _, hostDomain := range hostDomains {
		for _, domain := range t.domains {
			if npmDomainMatches(hostDomain, domain) || npmDomainMatches(domain, hostDomain) {
				return true
			}
		}
	}
	return false
}

func npmDomainMatches(pattern, domain string) bool {
	pattern, domain = strings.ToLower(strings.TrimSpace(pattern)), strings.ToLower(strings.TrimSpace(domain))
	if pattern == domain {
		return true
	}
	return strings.HasPrefix(pattern, "*.") && strings.HasSuffix(domain, pattern[1:])
}

func (t *NginxProxyManager) getHost(ctx context.Context, token string, id int64) (npmHost, error) {
	data, err := t.call(ctx, token, http.MethodGet, "/nginx/proxy-hosts/"+strconv.FormatInt(id, 10), nil)
	if err != nil {
		return npmHost{}, err
	}
	var host npmHost
	if json.Unmarshal(data, &host) != nil || host.ID <= 0 {
		return npmHost{}, errors.New("invalid NPM Proxy Host")
	}
	return host, nil
}

func (t *NginxProxyManager) checkCustomCertificate(ctx context.Context, token string, id int64) error {
	data, err := t.call(ctx, token, http.MethodGet, "/nginx/certificates/"+strconv.FormatInt(id, 10), nil)
	if err != nil {
		return err
	}
	var info struct {
		ID       int64  `json:"id"`
		Provider string `json:"provider"`
	}
	if json.Unmarshal(data, &info) != nil || info.ID <= 0 || info.Provider != "other" {
		return errors.New("NPM certificate is not a custom certificate")
	}
	return nil
}

func (t *NginxProxyManager) upload(ctx context.Context, token string, id int64, material Material) error {
	leaf, chain, err := splitCertificateChain(material.FullChainPEM)
	if err != nil {
		return err
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for _, part := range []struct {
		name, filename string
		content        []byte
	}{
		{"certificate", "certificate.pem", leaf}, {"certificate_key", "certificate.key", material.PrivateKeyPEM},
	} {
		field, err := writer.CreateFormFile(part.name, part.filename)
		if err != nil {
			return errors.New("prepare NPM certificate upload failed")
		}
		if _, err := field.Write(part.content); err != nil {
			return errors.New("prepare NPM certificate upload failed")
		}
	}
	if len(chain) > 0 {
		field, err := writer.CreateFormFile("intermediate_certificate", "intermediate.pem")
		if err != nil {
			return errors.New("prepare NPM chain upload failed")
		}
		if _, err := field.Write(chain); err != nil {
			return errors.New("prepare NPM chain upload failed")
		}
	}
	if err := writer.Close(); err != nil {
		return errors.New("finish NPM multipart upload failed")
	}
	path := "/api/nginx/certificates/" + strconv.FormatInt(id, 10) + "/upload"
	status, _, err := request(ctx, t.client, http.MethodPost, t.endpoint+path,
		map[string]string{"Authorization": "Bearer " + token, "Content-Type": writer.FormDataContentType()}, body.Bytes())
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("NPM certificate upload returned HTTP %d", status)
	}
	return nil
}

func (t *NginxProxyManager) call(ctx context.Context, token, method, path string, payload any) (json.RawMessage, error) {
	headers := map[string]string{}
	if token != "" {
		headers["Authorization"] = "Bearer " + token
	}
	status, content, err := requestJSON(ctx, t.client, method, t.endpoint+"/api"+path, headers, payload)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("NPM API returned HTTP %d", status)
	}
	if len(content) == 0 {
		return json.RawMessage(`null`), nil
	}
	if !json.Valid(content) {
		return nil, errors.New("invalid NPM API response")
	}
	return content, nil
}

var _ Target = (*NginxProxyManager)(nil)
