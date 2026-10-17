package deploy

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rainchen537/dnsgo"
)

type AMH struct {
	endpoint string
	apiKey   string
	envName  string
	vhosts   []string
	client   *http.Client
}

func init() {
	register("amh", func(config Config) (Target, error) {
		if config.Endpoint == "" {
			config.Endpoint = config.Values["url"]
		}
		endpoint, err := targetEndpoint(config, "")
		if err != nil {
			return nil, err
		}
		apiKey, envName := strings.TrimSpace(config.Values["apikey"]), strings.TrimSpace(config.Values["env_name"])
		vhosts := splitList(config.Values["vhost_name"])
		if apiKey == "" || envName == "" || len(vhosts) == 0 {
			return nil, errors.New("AMH API key, environment and virtual hosts are required")
		}
		return &AMH{endpoint: endpoint, apiKey: apiKey, envName: envName, vhosts: vhosts, client: client(config)}, nil
	})
}

func (t *AMH) Kind() string { return "amh" }

func (t *AMH) Check(ctx context.Context) error { _, err := t.login(ctx); return err }

func (t *AMH) Deploy(ctx context.Context, material Material) (Result, error) {
	if _, err := certificate(material); err != nil {
		return Result{}, err
	}
	token, err := t.login(ctx)
	if err != nil {
		return Result{}, err
	}
	result := Result{Target: t.Kind()}
	failures := 0
	for _, vhost := range t.vhosts {
		params := url.Values{"c": {"amssl"}, "a": {"admin_amssl"}, "envs_name": {t.envName}, "vhost_name": {vhost}, "ModuleSort": {"app"}}
		fields := url.Values{"submit_key_crt": {"y"}, "key_input1": {"key_input1"}, "key_content1": {string(material.PrivateKeyPEM)},
			"crt_input1": {"crt_input1"}, "crt_content1": {string(material.FullChainPEM)}, "amh_token": {token}}
		status, content, err := request(ctx, t.client, http.MethodPost, t.endpoint+"/?"+params.Encode(), map[string]string{
			"Cookie": t.cookie(), "Content-Type": "application/x-www-form-urlencoded",
		}, []byte(fields.Encode()))
		if err != nil || status != http.StatusOK || !strings.Contains(string(content), `<p id="success"`) {
			failures++
			if dnsgo.IsCode(err, dnsgo.CodeResultUnknown) || status == http.StatusOK && err == nil {
				result.Written = true
				return result, requestOutcomeError(t.Kind(), http.MethodPost, "AMH certificate write outcome is unconfirmed")
			}
			continue
		}
		result.Written = true
		if result.Location != "" {
			result.Location += ","
		}
		result.Location += vhost
	}
	if !result.Written {
		return result, errors.New("AMH certificate deployment failed for every virtual host")
	}
	if failures > 0 {
		return result, fmt.Errorf("AMH certificate deployment failed for %d virtual hosts", failures)
	}
	return result, nil
}

func (t *AMH) login(ctx context.Context) (string, error) {
	expires := fmt.Sprintf("amapi_expires=%d", time.Now().Unix()+120)
	mac := hmac.New(sha256.New, []byte(t.apiKey))
	_, _ = mac.Write([]byte(expires))
	body := expires + "&amapi_sign=" + hex.EncodeToString(mac.Sum(nil))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.endpoint+"/?c=amapi&a=login", strings.NewReader(body))
	if err != nil {
		return "", errors.New("invalid AMH login request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", t.cookie())
	httpClient := *t.client
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := httpClient.Do(req)
	if err != nil {
		return "", errors.New("AMH login request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusFound {
		return "", fmt.Errorf("AMH login failed (HTTP %d)", response.StatusCode)
	}
	location := response.Header.Get("Location")
	parsed, err := url.Parse(location)
	if err != nil {
		return "", errors.New("invalid AMH login redirect")
	}
	token := parsed.Query().Get("amh_token")
	if token == "" {
		return "", errors.New("AMH login did not return token")
	}
	return token, nil
}

func (t *AMH) cookie() string {
	mac := hmac.New(md5.New, []byte(t.apiKey))
	_, _ = mac.Write([]byte("php_sessid=" + t.apiKey))
	return "PHPSESSID=" + hex.EncodeToString(mac.Sum(nil))
}

var _ Target = (*AMH)(nil)
