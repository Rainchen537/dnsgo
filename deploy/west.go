package deploy

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/text/encoding/simplifiedchinese"
)

type West struct {
	endpoint    string
	username    string
	apiPassword string
	siteName    string
	domains     map[string]bool
	client      *http.Client
}

func init() {
	register("west", func(config Config) (Target, error) {
		endpoint, err := targetEndpoint(config, "https://api.west.cn/api/v2")
		if err != nil {
			return nil, err
		}
		username, password, site := strings.TrimSpace(config.Values["username"]), config.Values["api_password"], strings.TrimSpace(config.Values["sitename"])
		if username == "" || password == "" || site == "" {
			return nil, errors.New("West username, API password and FTP site name are required")
		}
		domains := make(map[string]bool)
		for _, domain := range splitList(config.Values["domainList"]) {
			domains[strings.ToLower(domain)] = true
		}
		return &West{endpoint: endpoint, username: username, apiPassword: password, siteName: site, domains: domains, client: client(config)}, nil
	})
}

func (t *West) Kind() string { return "west" }

func (t *West) Check(ctx context.Context) error {
	_, err := t.execute(ctx, url.Values{"act": {"products"}})
	return err
}

func (t *West) Deploy(ctx context.Context, material Material) (Result, error) {
	if _, err := certificate(material); err != nil {
		return Result{}, err
	}
	params := url.Values{"act": {"vhostssl"}, "sitename": {t.siteName}, "cmd": {"info"}}
	data, err := t.execute(ctx, params)
	if err != nil {
		return Result{}, err
	}
	var current struct {
		SSLEnabled json.RawMessage `json:"SSLEnabled"`
	}
	if err := json.Unmarshal(data, &current); err != nil {
		return Result{}, errors.New("invalid West SSL configuration")
	}
	params.Set("cmd", "import")
	params.Set("keycontent", string(material.PrivateKeyPEM))
	params.Set("certcontent", string(material.FullChainPEM))
	if _, err := t.execute(ctx, params); err != nil {
		return Result{Target: t.Kind(), Location: t.siteName, Written: true}, err
	}
	result := Result{Target: t.Kind(), Location: t.siteName, Written: true}
	params.Del("keycontent")
	params.Del("certcontent")
	if !westEnabled(current.SSLEnabled) {
		params.Set("cmd", "openssl")
		_, err = t.execute(ctx, params)
		return result, err
	}
	params.Set("cmd", "info")
	data, err = t.execute(ctx, params)
	if err != nil {
		return result, err
	}
	var updated struct {
		SSLCert struct {
			SSL map[string]struct {
				SysID json.RawMessage `json:"sysid"`
			} `json:"ssl"`
		} `json:"sslcert"`
	}
	if err := json.Unmarshal(data, &updated); err != nil {
		return result, errors.New("invalid West updated SSL configuration")
	}
	failures := 0
	for domain, item := range updated.SSLCert.SSL {
		if !t.domains[strings.ToLower(domain)] {
			continue
		}
		id := scalarID(item.SysID)
		if id == "" {
			failures++
			continue
		}
		cache := url.Values{"act": {"vhostssl"}, "sitename": {t.siteName}, "cmd": {"clearsslcache"}, "sslid": {id}, "dm": {domain}}
		if _, err := t.execute(ctx, cache); err != nil {
			failures++
		}
	}
	if failures > 0 {
		return result, fmt.Errorf("West SSL cache refresh failed for %d domains", failures)
	}
	return result, nil
}

func westEnabled(raw json.RawMessage) bool {
	s := strings.Trim(string(raw), `" `)
	return s != "" && s != "0" && s != "false" && s != "null"
}

func (t *West) execute(ctx context.Context, params url.Values) (json.RawMessage, error) {
	write := params.Get("cmd") == "import" || params.Get("cmd") == "openssl" || params.Get("cmd") == "clearsslcache"
	values := url.Values{}
	for key, list := range params {
		values[key] = append([]string(nil), list...)
	}
	timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
	hash := md5.Sum([]byte(t.username + t.apiPassword + timestamp))
	values.Set("username", t.username)
	values.Set("time", timestamp)
	values.Set("token", hex.EncodeToString(hash[:]))
	body := strings.ReplaceAll(values.Encode(), "+", "%20")
	status, content, err := request(ctx, t.client, http.MethodPost, t.endpoint+"/vhost/", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, []byte(body))
	if err != nil {
		return nil, err
	}
	decoded, err := simplifiedchinese.GBK.NewDecoder().Bytes(content)
	if err != nil {
		if write {
			return nil, requestOutcomeError(t.Kind(), http.MethodPost, "West certificate write response could not be decoded")
		}
		return nil, errors.New("West response GBK decoding failed")
	}
	var response struct {
		Result *int            `json:"result"`
		Data   json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(decoded, &response); err != nil {
		if write {
			return nil, requestOutcomeError(t.Kind(), http.MethodPost, "invalid West certificate write response")
		}
		return nil, errors.New("invalid West API response")
	}
	if response.Result == nil {
		if write {
			return nil, requestOutcomeError(t.Kind(), http.MethodPost, "West certificate write returned no result code")
		}
		return nil, errors.New("West API returned no result code")
	}
	if status < 200 || status >= 300 || *response.Result != 200 {
		return nil, fmt.Errorf("West API rejected request (HTTP %d, code %d)", status, *response.Result)
	}
	return response.Data, nil
}

var _ Target = (*West)(nil)
