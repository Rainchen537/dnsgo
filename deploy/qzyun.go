package deploy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	stdhtml "html"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

const qzyunRouterState = `%5B%22%22%2C%7B%22children%22%3A%5B%22(app)%22%2C%7B%22children%22%3A%5B%22(product)%22%2C%7B%22children%22%3A%5B%22certificate%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%2Ctrue%5D`

var qzyunDocumentID = regexp.MustCompile(`(?i)^[a-z0-9]{24}$`)
var qzyunScripts = regexp.MustCompile(`<script[^>]+src=["']([^"']+\.js[^"']*)["']`)
var qzyunRSC = regexp.MustCompile(`(?s)self\.__next_f\.push\((\[.*?\])\)</script>`)
var qzyunActionResult = regexp.MustCompile(`(?m)(?:^|\n)[a-z0-9]+:(\{[^\r\n]*\})`)
var errQZNotFound = errors.New("QZCloud certificate was not found")

type QZYun struct {
	endpoint    string
	email       string
	password    string
	certificate string
	domain      string
	client      *http.Client
}

type qzyunSession struct {
	target  *QZYun
	cookies map[string]string
	actions map[string]string
	added   bool
}

type qzyunResponse struct {
	status   int
	body     string
	location string
	headers  http.Header
}

func init() {
	register("qzyun", func(config Config) (Target, error) {
		endpoint, err := targetEndpoint(config, "https://panel.qzyun.cn")
		if err != nil {
			return nil, err
		}
		email, password := strings.TrimSpace(config.Values["email"]), config.Values["password"]
		if email == "" || password == "" || !strings.Contains(email, "@") {
			return nil, errors.New("QZCloud login email and password are required")
		}
		return &QZYun{endpoint: endpoint, email: email, password: password,
			certificate: strings.TrimSpace(config.Values["certificate"]), domain: strings.TrimSpace(config.Values["domain"]), client: client(config)}, nil
	})
}

func (t *QZYun) Kind() string { return "qzyun" }

func (t *QZYun) Check(ctx context.Context) error {
	session := qzyunSession{target: t, cookies: map[string]string{}, actions: map[string]string{}}
	return session.login(ctx)
}

func (t *QZYun) Deploy(ctx context.Context, material Material) (Result, error) {
	if _, err := certificate(material); err != nil {
		return Result{}, err
	}
	if t.certificate == "" {
		return Result{}, errors.New("QZCloud certificate name or document ID is required")
	}
	session := qzyunSession{target: t, cookies: map[string]string{}, actions: map[string]string{}}
	if err := session.login(ctx); err != nil {
		return Result{}, err
	}
	page, err := session.request(ctx, http.MethodGet, "/certificate", nil, nil)
	if err != nil {
		return Result{}, err
	}
	if page.status != http.StatusOK {
		return Result{}, fmt.Errorf("QZCloud certificate page returned HTTP %d", page.status)
	}
	result := Result{Target: t.Kind()}
	documentID := t.certificate
	if !qzyunDocumentID.MatchString(documentID) {
		documentID, err = qzyunFindCertificate(page.body, t.certificate)
		if errors.Is(err, errQZNotFound) {
			documentID, err = session.addCertificate(ctx, page.body, t.certificate, material)
			if session.added {
				result.Written = true
			}
		}
		if err != nil {
			return result, err
		}
	}
	result.Location = documentID
	if !session.added {
		action, err := session.findAction(ctx, page.body, "updateCertificateAction")
		if err != nil {
			return result, err
		}
		response, err := session.postAction(ctx, "/certificate", action, map[string]string{
			"1_certDocumentId": documentID, "1_serverCertificate": string(material.FullChainPEM),
			"1_privateKey": string(material.PrivateKeyPEM), "0": `[{"success":false,"message":""},"$K1"]`,
		})
		if err != nil {
			return result, err
		}
		if response.status != http.StatusOK || !qzyunActionSuccess(response.body) {
			return result, errors.New("QZCloud certificate update failed")
		}
		result.Written = true
	}
	if t.domain != "" {
		if err := session.bindDomain(ctx, documentID, t.certificate, t.domain, material); err != nil {
			return result, err
		}
		result.Written = true
	}
	return result, nil
}

func (s *qzyunSession) login(ctx context.Context) error {
	page, err := s.request(ctx, http.MethodGet, "/login", nil, nil)
	if err != nil {
		return err
	}
	if page.status != http.StatusOK {
		return fmt.Errorf("QZCloud login page returned HTTP %d", page.status)
	}
	action, err := s.findAction(ctx, page.body, "login")
	if err != nil {
		return err
	}
	response, err := s.postAction(ctx, "/login", action, map[string]string{
		"1_email": s.target.email, "1_password": s.target.password, "0": `[{"error":null,"success":false},"$K1"]`,
	})
	if err != nil {
		return err
	}
	if response.status < 300 || response.status >= 400 {
		if response.status != http.StatusOK || !qzyunActionSuccess(response.body) {
			return errors.New("QZCloud login failed")
		}
	}
	if len(s.cookies) == 0 {
		return errors.New("QZCloud login returned no session cookie")
	}
	return nil
}

func (s *qzyunSession) addCertificate(ctx context.Context, page, name string, material Material) (string, error) {
	action, err := s.findAction(ctx, page, "addCertificateAction")
	if err != nil {
		return "", err
	}
	response, err := s.postAction(ctx, "/certificate", action, map[string]string{
		"1_certificateName": name, "1_serverCertificate": string(material.FullChainPEM),
		"1_privateKey": string(material.PrivateKeyPEM), "0": `[{"success":false,"message":""},"$K1"]`,
	})
	if err != nil {
		return "", err
	}
	if response.status != http.StatusOK || !qzyunActionSuccess(response.body) {
		return "", errors.New("QZCloud certificate creation failed")
	}
	s.added = true
	pageResponse, err := s.request(ctx, http.MethodGet, "/certificate", nil, nil)
	if err != nil {
		return "", err
	}
	if pageResponse.status != http.StatusOK {
		return "", errors.New("QZCloud certificate created but listing failed")
	}
	id, err := qzyunFindCertificate(pageResponse.body, name)
	if err != nil {
		return "", errors.New("QZCloud certificate created but document ID could not be resolved")
	}
	return id, nil
}

func (s *qzyunSession) bindDomain(ctx context.Context, documentID, configuredName, domain string, material Material) error {
	domainPage, err := s.request(ctx, http.MethodGet, "/cdn/domain/"+url.PathEscape(domain), nil, nil)
	if err != nil {
		return err
	}
	if domainPage.status != http.StatusOK {
		return fmt.Errorf("QZCloud domain page returned HTTP %d", domainPage.status)
	}
	domainInfo, err := qzyunFindDomain(domainPage.body, domain)
	if err != nil {
		return err
	}
	certificatePage, err := s.request(ctx, http.MethodGet, "/certificate", nil, nil)
	if err != nil {
		return err
	}
	if certificatePage.status != http.StatusOK {
		return errors.New("QZCloud certificate listing failed before binding")
	}
	if qzyunCertificateBound(certificatePage.body, documentID, domain) {
		return nil
	}
	action, err := s.findAction(ctx, certificatePage.body, "bindDomainCdnServer")
	if err != nil {
		return err
	}
	name := configuredName
	if qzyunDocumentID.MatchString(configuredName) {
		name, err = qzyunCertificateName(certificatePage.body, documentID)
		if err != nil {
			return err
		}
	}
	response, err := s.postAction(ctx, "/certificate", action, map[string]string{
		"1_domainName": domain, "1_Id": domainInfo.ID, "1_documentId": domainInfo.DocumentID,
		"1_CertificateName": name, "1_ServerCertificate": string(material.FullChainPEM),
		"1_CertificateDocumentId": documentID, "1_PrivateKey": string(material.PrivateKeyPEM),
		"0": `[{"success":false,"message":""},"$K1"]`,
	})
	if err != nil {
		return err
	}
	if response.status != http.StatusOK || !qzyunActionSuccess(response.body) {
		return errors.New("QZCloud certificate domain binding failed")
	}
	return nil
}

func (s *qzyunSession) findAction(ctx context.Context, page, name string) (string, error) {
	if id := s.actions[name]; id != "" {
		return id, nil
	}
	match := regexp.MustCompile(`(?s)createServerReference\)\("([a-f0-9]{32,64})".{0,300},"` + regexp.QuoteMeta(name) + `"\)`)
	seen := map[string]bool{}
	for _, found := range qzyunScripts.FindAllStringSubmatch(page, -1) {
		src := stdhtml.UnescapeString(found[1])
		address, err := url.Parse(src)
		if err != nil {
			continue
		}
		base, _ := url.Parse(s.target.endpoint)
		resolved := base.ResolveReference(address)
		if resolved.Host != base.Host || resolved.Scheme != base.Scheme || seen[resolved.String()] {
			continue
		}
		seen[resolved.String()] = true
		response, err := s.request(ctx, http.MethodGet, resolved.String(), nil, nil)
		if err != nil || response.status != http.StatusOK {
			continue
		}
		if id := match.FindStringSubmatch(response.body); len(id) > 1 {
			s.actions[name] = id[1]
			return id[1], nil
		}
	}
	return "", fmt.Errorf("QZCloud action %s was not found; page assets may have changed", name)
}

func (s *qzyunSession) postAction(ctx context.Context, path, action string, fields map[string]string) (qzyunResponse, error) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for name, value := range fields {
		if err := writer.WriteField(name, value); err != nil {
			return qzyunResponse{}, errors.New("prepare QZCloud action failed")
		}
	}
	if err := writer.Close(); err != nil {
		return qzyunResponse{}, errors.New("prepare QZCloud action failed")
	}
	return s.request(ctx, http.MethodPost, path, body.Bytes(), map[string]string{
		"Accept": "text/x-component", "next-action": action, "next-router-state-tree": qzyunRouterState,
		"Content-Type": writer.FormDataContentType(),
	})
}

func (s *qzyunSession) request(ctx context.Context, method, path string, body []byte, headers map[string]string) (qzyunResponse, error) {
	address := path
	if !strings.HasPrefix(path, "https://") && !strings.HasPrefix(path, "http://") {
		address = s.target.endpoint + path
	}
	req, err := http.NewRequestWithContext(ctx, method, address, bytes.NewReader(body))
	if err != nil {
		return qzyunResponse{}, errors.New("invalid QZCloud request")
	}
	req.Header.Set("Referer", s.target.endpoint+"/")
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	for name, value := range s.cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	httpClient := *s.target.client
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := httpClient.Do(req)
	if err != nil {
		return qzyunResponse{}, requestOutcomeError("qzyun", method, "request failed")
	}
	defer response.Body.Close()
	if (response.StatusCode == http.StatusRequestTimeout || response.StatusCode >= 500) && method != http.MethodGet {
		return qzyunResponse{}, requestOutcomeError("qzyun", method, "server error after write request")
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, 16<<20))
	if err != nil {
		return qzyunResponse{}, requestOutcomeError("qzyun", method, "response read failed")
	}
	for _, cookie := range response.Cookies() {
		if cookie.Name == "" {
			continue
		}
		if cookie.Value == "" || cookie.Value == "deleted" || cookie.MaxAge < 0 {
			delete(s.cookies, cookie.Name)
		} else {
			s.cookies[cookie.Name] = cookie.Value
		}
	}
	return qzyunResponse{status: response.StatusCode, body: string(content), location: response.Header.Get("Location"), headers: response.Header.Clone()}, nil
}

func qzyunActionSuccess(body string) bool {
	matches := qzyunActionResult.FindAllStringSubmatch(body, -1)
	for i := len(matches) - 1; i >= 0; i-- {
		var result struct {
			Success *bool           `json:"success"`
			Error   json.RawMessage `json:"error"`
			Message json.RawMessage `json:"message"`
		}
		if json.Unmarshal([]byte(matches[i][1]), &result) == nil && (result.Success != nil || len(result.Error) > 0 || len(result.Message) > 0) {
			return result.Success != nil && *result.Success
		}
	}
	return false
}

func qzyunExtractRSC(page string) string {
	var result strings.Builder
	for _, match := range qzyunRSC.FindAllStringSubmatch(page, -1) {
		var payload []json.RawMessage
		if json.Unmarshal([]byte(match[1]), &payload) != nil || len(payload) < 2 || string(payload[0]) != "1" {
			continue
		}
		var text string
		if json.Unmarshal(payload[1], &text) == nil {
			result.WriteString(text)
		}
	}
	return result.String()
}

func qzyunObjects(page, key, value string) []map[string]json.RawMessage {
	rsc := qzyunExtractRSC(page)
	quoted, _ := json.Marshal(value)
	needle := `"` + key + `":` + string(quoted)
	var results []map[string]json.RawMessage
	for offset := 0; offset < len(rsc); {
		index := strings.Index(rsc[offset:], needle)
		if index < 0 {
			break
		}
		position := offset + index
		start := strings.LastIndex(rsc[:position], `{"id":`)
		if start >= 0 {
			if object := qzyunJSONObject(rsc, start); object != "" {
				var decoded map[string]json.RawMessage
				if json.Unmarshal([]byte(object), &decoded) == nil {
					results = append(results, decoded)
				}
			}
		}
		offset = position + len(needle)
	}
	return results
}

func qzyunJSONObject(text string, start int) string {
	depth, inString, escaped := 0, false, false
	for index := start; index < len(text); index++ {
		switch char := text[index]; {
		case inString:
			if escaped {
				escaped = false
			} else if char == '\\' {
				escaped = true
			} else if char == '"' {
				inString = false
			}
		case char == '"':
			inString = true
		case char == '{':
			depth++
		case char == '}':
			depth--
			if depth == 0 {
				return text[start : index+1]
			}
		}
	}
	return ""
}

func qzyunFindCertificate(page, name string) (string, error) {
	ids := map[string]bool{}
	for _, object := range qzyunObjects(page, "name", name) {
		if object["startTime"] == nil || object["privateKey"] == nil || object["content"] == nil {
			continue
		}
		var id string
		if json.Unmarshal(object["documentId"], &id) == nil && id != "" {
			ids[id] = true
		}
	}
	if len(ids) > 1 {
		return "", errors.New("QZCloud contains duplicate certificate names; use document ID")
	}
	for id := range ids {
		return id, nil
	}
	return "", errQZNotFound
}

type qzyunDomainInfo struct {
	ID         string
	DocumentID string
}

func qzyunFindDomain(page, domain string) (qzyunDomainInfo, error) {
	for _, object := range qzyunObjects(page, "domain", domain) {
		id := scalarID(object["id"])
		var documentID string
		_ = json.Unmarshal(object["documentId"], &documentID)
		if id != "" && documentID != "" {
			return qzyunDomainInfo{ID: id, DocumentID: documentID}, nil
		}
	}
	return qzyunDomainInfo{}, errors.New("QZCloud domain was not found")
}

func qzyunCertificateBound(page, documentID, domain string) bool {
	for _, object := range qzyunObjects(page, "documentId", documentID) {
		var domains []struct {
			Domain string `json:"domain"`
		}
		if json.Unmarshal(object["cdnDomains"], &domains) == nil {
			for _, item := range domains {
				if item.Domain == domain {
					return true
				}
			}
		}
	}
	return false
}

func qzyunCertificateName(page, documentID string) (string, error) {
	for _, object := range qzyunObjects(page, "documentId", documentID) {
		if object["content"] == nil {
			continue
		}
		var name string
		if json.Unmarshal(object["name"], &name) == nil && name != "" {
			return name, nil
		}
	}
	return "", errors.New("QZCloud certificate name was not found")
}

var _ Target = (*QZYun)(nil)
