package deploy

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/rainchen537/dnsgo"
)

type Kangle struct {
	kind     string
	endpoint string
	path     string
	auth     string
	username string
	password string
	skey     string
	account  string
	domains  []string
	client   *http.Client
}

func init() {
	for _, name := range []string{"kangle", "kangleadmin"} {
		kind := name
		register(kind, func(config Config) (Target, error) {
			if config.Endpoint == "" {
				config.Endpoint = config.Values["url"]
			}
			endpoint, err := targetEndpoint(config, "")
			if err != nil {
				return nil, err
			}
			target := &Kangle{kind: kind, endpoint: endpoint, auth: config.Values["auth"], username: strings.TrimSpace(config.Values["username"]),
				password: config.Values["password"], skey: config.Values["skey"], account: config.Values["name"], client: client(config)}
			if target.username == "" {
				return nil, errors.New("Kangle username is required")
			}
			if kind == "kangleadmin" {
				target.path = strings.TrimRight(config.Values["path"], "/")
				if target.path == "" {
					target.path = "/admin"
				}
				if target.skey == "" || target.account == "" {
					return nil, errors.New("Kangle admin SSO key and website account are required")
				}
			} else if target.auth == "1" && target.skey == "" || kind == "kangle" && target.auth != "1" && target.password == "" {
				return nil, errors.New("Kangle password or SSO key is required")
			}
			if config.Values["type"] == "1" {
				target.domains = splitList(config.Values["domains"])
			}
			return target, nil
		})
	}
}

func (t *Kangle) Kind() string { return t.kind }

func (t *Kangle) Check(ctx context.Context) error { _, err := t.login(ctx); return err }

func (t *Kangle) Deploy(ctx context.Context, material Material) (Result, error) {
	if _, err := certificate(material); err != nil {
		return Result{}, err
	}
	cookie, err := t.login(ctx)
	if err != nil {
		return Result{}, err
	}
	if t.kind == "kangleadmin" {
		path := t.path + "/index.php?c=vhost&a=impLogin&name=" + url.QueryEscape(t.account)
		status, _, _, err := t.send(ctx, http.MethodGet, path, nil, cookie, "")
		if err != nil || status != http.StatusFound {
			return Result{}, errors.New("Kangle website account login failed")
		}
	}
	status, _, _, err := t.send(ctx, http.MethodGet, "/vhost/", nil, cookie, "")
	if err != nil {
		return Result{}, err
	}
	if status < 200 || status >= 400 {
		return Result{}, errors.New("Kangle website account session check failed")
	}
	if len(t.domains) == 0 {
		if err := t.deployOne(ctx, cookie, "", material); err != nil {
			return Result{Target: t.Kind(), Location: "account", Written: dnsgo.IsCode(err, dnsgo.CodeResultUnknown)}, err
		}
		return Result{Target: t.Kind(), Location: "account", Written: true}, nil
	}
	result := Result{Target: t.Kind()}
	failures := 0
	for _, domain := range t.domains {
		if err := t.deployOne(ctx, cookie, domain, material); err != nil {
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
		result.Location += domain
	}
	if !result.Written {
		return result, errors.New("Kangle domain deployment failed for every target")
	}
	if failures > 0 {
		return result, fmt.Errorf("Kangle domain deployment failed for %d targets", failures)
	}
	return result, nil
}

func (t *Kangle) deployOne(ctx context.Context, cookie, domain string, material Material) error {
	path := "/vhost/?c=ssl&a=ssl"
	values := url.Values{"certificate": {string(material.FullChainPEM)}, "certificate_key": {string(material.PrivateKeyPEM)}}
	if domain != "" {
		path = "/vhost/?c=ssl&a=domainSsl"
		values.Set("domain", domain)
	}
	status, content, _, err := t.send(ctx, http.MethodPost, path, []byte(values.Encode()), cookie, "")
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 || !strings.Contains(string(content), "成功") {
		if status >= 200 && status < 300 {
			return requestOutcomeError(t.Kind(), http.MethodPost, "Kangle certificate write response is unconfirmed")
		}
		return fmt.Errorf("Kangle deployment rejected (HTTP %d)", status)
	}
	return nil
}

func (t *Kangle) login(ctx context.Context) (string, error) {
	if t.kind == "kangle" && t.auth != "1" {
		values := url.Values{"username": {t.username}, "passwd": {t.password}}
		status, _, cookies, err := t.send(ctx, http.MethodPost, "/vhost/index.php?c=session&a=login", []byte(values.Encode()), "",
			t.endpoint+"/vhost/index.php?c=session&a=loginForm")
		if err != nil || status != http.StatusFound || cookies == "" {
			return "", errors.New("Kangle password login failed")
		}
		return cookies, nil
	}
	basePath := "/vhost"
	if t.kind == "kangleadmin" {
		basePath = t.path
	}
	returnURL := t.endpoint + "/index.php?"
	if t.kind == "kangleadmin" {
		returnURL = t.endpoint + t.path + "/index.php?"
	}
	path := basePath + "/index.php?c=sso&a=hello&url=" + url.QueryEscape(returnURL)
	location, cookies, err := t.ssoChallenge(ctx, path)
	if err != nil {
		return "", err
	}
	parsed, err := url.Parse(location)
	if err != nil {
		return "", errors.New("invalid Kangle SSO redirect")
	}
	sessionKey := parsed.Query().Get("r")
	if sessionKey == "" {
		return "", errors.New("Kangle SSO challenge key is missing")
	}
	hash := md5.Sum([]byte(sessionKey + t.username + sessionKey + t.skey))
	params := url.Values{"c": {"sso"}, "a": {"login"}, "name": {t.username}, "r": {sessionKey}, "s": {hex.EncodeToString(hash[:])}}
	status, _, _, err := t.send(ctx, http.MethodGet, basePath+"/index.php?"+params.Encode(), nil, cookies, "")
	if err != nil || status != http.StatusFound {
		return "", errors.New("Kangle SSO login failed")
	}
	return cookies, nil
}

func (t *Kangle) ssoChallenge(ctx context.Context, path string) (string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.endpoint+path, nil)
	if err != nil {
		return "", "", errors.New("invalid Kangle SSO request")
	}
	httpClient := *t.client
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := httpClient.Do(req)
	if err != nil {
		return "", "", errors.New("Kangle SSO request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusFound {
		return "", "", errors.New("Kangle SSO redirect missing")
	}
	var cookies []string
	for _, item := range response.Cookies() {
		if item.Name != "" && item.Value != "" && item.Value != "deleted" {
			cookies = append(cookies, item.Name+"="+item.Value)
		}
	}
	location := response.Header.Get("Location")
	if location == "" || len(cookies) == 0 {
		return "", "", errors.New("Kangle SSO challenge is incomplete")
	}
	return location, strings.Join(cookies, "; "), nil
}

func (t *Kangle) send(ctx context.Context, method, path string, body []byte, cookie, referer string) (int, []byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, method, t.endpoint+path, strings.NewReader(string(body)))
	if err != nil {
		return 0, nil, "", errors.New("invalid Kangle request")
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	if referer != "" {
		req.Header.Set("Referer", referer)
	}
	httpClient := *t.client
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := httpClient.Do(req)
	if err != nil {
		return 0, nil, "", requestOutcomeError("kangle", method, "request failed")
	}
	defer response.Body.Close()
	if (response.StatusCode == http.StatusRequestTimeout || response.StatusCode >= 500) && method != http.MethodGet {
		return 0, nil, "", requestOutcomeError("kangle", method, "server error after write request")
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		return 0, nil, "", requestOutcomeError("kangle", method, "response read failed")
	}
	var cookies []string
	for _, item := range response.Cookies() {
		if item.Name != "" && item.Value != "" && item.Value != "deleted" {
			cookies = append(cookies, item.Name+"="+item.Value)
		}
	}
	return response.StatusCode, content, strings.Join(cookies, "; "), nil
}

var _ Target = (*Kangle)(nil)
