package deploy

import (
	"context"
	"errors"
	"fmt"
	stdhtml "html"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/rainchen537/dnsgo"
	xhtml "golang.org/x/net/html"
)

type CloudPanel struct {
	endpoint string
	username string
	password string
	sites    []string
	client   *http.Client
}

type cloudPanelSession struct {
	target  *CloudPanel
	cookies map[string]string
}

type cloudPanelResponse struct {
	status   int
	body     string
	location string
}

func init() {
	register("cloudpanel", func(config Config) (Target, error) {
		if config.Endpoint == "" {
			config.Endpoint = config.Values["url"]
		}
		endpoint, err := targetEndpoint(config, "")
		if err != nil {
			return nil, err
		}
		username, password := strings.TrimSpace(config.Values["username"]), config.Values["password"]
		if username == "" || password == "" {
			return nil, errors.New("CloudPanel username and password are required")
		}
		return &CloudPanel{endpoint: endpoint, username: username, password: password, sites: splitList(config.Values["sites"]), client: client(config)}, nil
	})
}

func (t *CloudPanel) Kind() string { return "cloudpanel" }

func (t *CloudPanel) Check(ctx context.Context) error {
	session := cloudPanelSession{target: t, cookies: map[string]string{}}
	return session.login(ctx)
}

func (t *CloudPanel) Deploy(ctx context.Context, material Material) (Result, error) {
	if _, err := certificate(material); err != nil {
		return Result{}, err
	}
	if len(t.sites) == 0 {
		return Result{}, errors.New("CloudPanel site domains are required")
	}
	session := cloudPanelSession{target: t, cookies: map[string]string{}}
	if err := session.login(ctx); err != nil {
		return Result{}, err
	}
	result := Result{Target: t.Kind()}
	failures := 0
	for _, site := range t.sites {
		if err := session.deploySite(ctx, site, material); err != nil {
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
	if !result.Written {
		return result, errors.New("CloudPanel certificate deployment failed for every site")
	}
	if failures > 0 {
		return result, fmt.Errorf("CloudPanel certificate deployment failed for %d sites", failures)
	}
	return result, nil
}

func (s *cloudPanelSession) login(ctx context.Context) error {
	page, err := s.request(ctx, http.MethodGet, "/login", nil, "")
	if err != nil {
		return err
	}
	if page.status != http.StatusOK {
		return fmt.Errorf("CloudPanel login page returned HTTP %d", page.status)
	}
	csrf := cloudPanelInput(page.body, "name", "_csrf_token")
	if csrf == "" {
		return errors.New("CloudPanel login CSRF token is missing")
	}
	values := url.Values{"userName": {s.target.username}, "password": {s.target.password}, "_csrf_token": {csrf}}
	response, err := s.request(ctx, http.MethodPost, "/login", values, s.target.endpoint+"/login")
	if err != nil {
		return err
	}
	if cloudPanelTwoFactor(response.location) || cloudPanelTwoFactor(response.body) {
		return errors.New("CloudPanel two-factor login is not supported")
	}
	if response.status >= 300 && response.status < 400 {
		if len(s.cookies) == 0 {
			return errors.New("CloudPanel login returned no session cookie")
		}
		path := cloudPanelLocationPath(response.location)
		if path == "" {
			path = "/"
		}
		page, err = s.request(ctx, http.MethodGet, path, nil, "")
		if err != nil {
			return err
		}
		if cloudPanelLoginPage(page) {
			return errors.New("CloudPanel login was not accepted")
		}
		return nil
	}
	return errors.New("CloudPanel login was not accepted")
}

func (s *cloudPanelSession) deploySite(ctx context.Context, site string, material Material) error {
	path := "/site/" + url.PathEscape(site) + "/certificate/import"
	page, err := s.request(ctx, http.MethodGet, path, nil, "")
	if err != nil {
		return err
	}
	if page.status != http.StatusOK || cloudPanelLoginPage(page) {
		return fmt.Errorf("CloudPanel certificate import page failed (HTTP %d)", page.status)
	}
	token := cloudPanelInput(page.body, "name", "site_import_certificate[_token]")
	if token == "" {
		token = cloudPanelInput(page.body, "id", "site_import_certificate__token")
	}
	if token == "" {
		return errors.New("CloudPanel certificate form token is missing")
	}
	values := url.Values{
		"site_import_certificate[privateKey]":       {string(material.PrivateKeyPEM)},
		"site_import_certificate[certificate]":      {string(material.FullChainPEM)},
		"site_import_certificate[certificateChain]": {""},
		"site_import_certificate[submit]":           {"Import and Install"},
		"site_import_certificate[_token]":           {token},
	}
	response, err := s.request(ctx, http.MethodPost, path, values, s.target.endpoint+path)
	if err != nil {
		return err
	}
	if response.status >= 300 && response.status < 400 {
		location := cloudPanelLocationPath(response.location)
		if location == "/login" {
			return errors.New("CloudPanel login expired during certificate import")
		}
		if strings.Contains(location, "/certificates") || strings.Contains(location, "/site/"+site) {
			return nil
		}
	}
	if strings.Contains(response.body, `class="alert alert-danger"`) || strings.Contains(response.body, `class="alert alert-warning"`) {
		return errors.New("CloudPanel certificate form reported an error")
	}
	if response.status == http.StatusOK && strings.Contains(response.body, "site_import_certificate") {
		return errors.New("CloudPanel certificate form was not accepted")
	}
	if response.status < 200 || response.status >= 300 {
		return fmt.Errorf("CloudPanel certificate import returned HTTP %d", response.status)
	}
	return nil
}

func (s *cloudPanelSession) request(ctx context.Context, method, path string, values url.Values, referer string) (cloudPanelResponse, error) {
	address := path
	if !strings.HasPrefix(path, "https://") && !strings.HasPrefix(path, "http://") {
		address = s.target.endpoint + path
	}
	var body io.Reader
	if values != nil {
		body = strings.NewReader(values.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, address, body)
	if err != nil {
		return cloudPanelResponse{}, errors.New("invalid CloudPanel request")
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", s.target.endpoint)
	}
	if referer == "" {
		referer = s.target.endpoint + "/"
	}
	req.Header.Set("Referer", referer)
	if len(s.cookies) > 0 {
		names := make([]string, 0, len(s.cookies))
		for name := range s.cookies {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			req.AddCookie(&http.Cookie{Name: name, Value: s.cookies[name]})
		}
	}
	httpClient := *s.target.client
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := httpClient.Do(req)
	if err != nil {
		if path == "/login" {
			return cloudPanelResponse{}, errors.New("CloudPanel login request failed")
		}
		return cloudPanelResponse{}, requestOutcomeError("cloudpanel", method, "request failed")
	}
	defer response.Body.Close()
	if (response.StatusCode == http.StatusRequestTimeout || response.StatusCode >= 500) && method != http.MethodGet && path != "/login" {
		return cloudPanelResponse{}, requestOutcomeError("cloudpanel", method, "server error after write request")
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		if path == "/login" {
			return cloudPanelResponse{}, errors.New("read CloudPanel login response failed")
		}
		return cloudPanelResponse{}, requestOutcomeError("cloudpanel", method, "response read failed")
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
	return cloudPanelResponse{status: response.StatusCode, body: string(content), location: response.Header.Get("Location")}, nil
}

func cloudPanelInput(page, attribute, value string) string {
	root, err := xhtml.Parse(strings.NewReader(page))
	if err != nil {
		return ""
	}
	var visit func(*xhtml.Node) string
	visit = func(node *xhtml.Node) string {
		if node.Type == xhtml.ElementNode && node.Data == "input" {
			var matched, content string
			for _, attr := range node.Attr {
				if attr.Key == attribute && attr.Val == value {
					matched = "yes"
				}
				if attr.Key == "value" {
					content = attr.Val
				}
			}
			if matched != "" {
				return stdhtml.UnescapeString(content)
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			if found := visit(child); found != "" {
				return found
			}
		}
		return ""
	}
	return visit(root)
}

func cloudPanelLocationPath(location string) string {
	parsed, err := url.Parse(location)
	if err != nil {
		return ""
	}
	return parsed.Path
}

func cloudPanelLoginPage(response cloudPanelResponse) bool {
	return cloudPanelLocationPath(response.location) == "/login" || strings.Contains(response.body, `name="userName"`) && strings.Contains(response.body, `action="/login"`)
}

func cloudPanelTwoFactor(value string) bool {
	value = strings.ToLower(value)
	return strings.Contains(value, "2fa") || strings.Contains(value, "two-factor") || strings.Contains(value, "totp") || strings.Contains(value, "authenticator") || strings.Contains(value, "one-time password")
}

var _ Target = (*CloudPanel)(nil)
