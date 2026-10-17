package deploy

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type UniCloud struct {
	username string
	password string
	deviceID string
	domains  []string
	provider string
	spaceID  string
	client   *http.Client
}

type uniClientInfo struct {
	Platform           string `json:"PLATFORM"`
	OS                 string `json:"OS"`
	UpperAppID         string `json:"APPID"`
	UpperDeviceID      string `json:"DEVICEID"`
	Scene              int    `json:"scene"`
	AppID              string `json:"appId"`
	AppLanguage        string `json:"appLanguage"`
	AppName            string `json:"appName"`
	AppVersion         string `json:"appVersion"`
	AppVersionCode     string `json:"appVersionCode"`
	BrowserName        string `json:"browserName"`
	BrowserVersion     string `json:"browserVersion"`
	DeviceID           string `json:"deviceId"`
	DeviceModel        string `json:"deviceModel"`
	DeviceType         string `json:"deviceType"`
	HostName           string `json:"hostName"`
	HostVersion        string `json:"hostVersion"`
	OSName             string `json:"osName"`
	OSVersion          string `json:"osVersion"`
	UA                 string `json:"ua"`
	UniCompilerVersion string `json:"uniCompilerVersion"`
	UniPlatform        string `json:"uniPlatform"`
	UniRuntimeVersion  string `json:"uniRuntimeVersion"`
	Locale             string `json:"locale"`
	UpperLocale        string `json:"LOCALE"`
}

type uniChallenge struct {
	Version     json.RawMessage `json:"version"`
	Algorithm   string          `json:"algorithm"`
	KeyID       string          `json:"keyId"`
	ChallengeID string          `json:"challengeId"`
	PublicKey   string          `json:"publicKey"`
}

type uniEnvelopeHeader struct {
	Version     json.RawMessage `json:"version"`
	Algorithm   string          `json:"algorithm"`
	KeyID       string          `json:"keyId"`
	ChallengeID string          `json:"challengeId"`
}

type uniEnvelope struct {
	Version      json.RawMessage `json:"version"`
	Algorithm    string          `json:"algorithm"`
	KeyID        string          `json:"keyId"`
	ChallengeID  string          `json:"challengeId"`
	EncryptedKey string          `json:"encryptedKey"`
	IV           string          `json:"iv"`
	Ciphertext   string          `json:"ciphertext"`
	Tag          string          `json:"tag"`
}

func init() {
	register("unicloud", func(config Config) (Target, error) {
		username, password := strings.TrimSpace(config.Values["username"]), config.Values["password"]
		domains := splitList(config.Values["domains"])
		provider, spaceID := strings.TrimSpace(config.Values["provider"]), strings.TrimSpace(config.Values["spaceId"])
		if username == "" || password == "" || provider == "" || spaceID == "" || len(domains) == 0 {
			return nil, errors.New("UniCloud account, provider, space and domains are required")
		}
		var random [7]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, errors.New("UniCloud device ID generation failed")
		}
		var digits strings.Builder
		for _, value := range random {
			digits.WriteByte('0' + value%10)
		}
		deviceID := strconv.FormatInt(time.Now().UnixMilli(), 10) + digits.String()
		return &UniCloud{username: username, password: password, deviceID: deviceID, domains: domains,
			provider: provider, spaceID: spaceID, client: client(config)}, nil
	})
}

func (t *UniCloud) Kind() string { return "unicloud" }

func (t *UniCloud) Check(ctx context.Context) error { _, err := t.login(ctx); return err }

func (t *UniCloud) Deploy(ctx context.Context, material Material) (Result, error) {
	if _, err := certificate(material); err != nil {
		return Result{}, err
	}
	token, err := t.getToken(ctx)
	if err != nil {
		return Result{}, err
	}
	result := Result{Target: t.Kind()}
	for _, domain := range t.domains {
		payload := map[string]string{"appid": "", "provider": t.provider, "spaceId": t.spaceID, "domain": domain,
			"cert": rawURLEncode(string(material.FullChainPEM)), "key": rawURLEncode(string(material.PrivateKeyPEM))}
		status, content, err := requestJSON(ctx, t.client, http.MethodPost,
			"https://unicloud-api.dcloud.net.cn/unicloud/api/host/create-domain-with-cert", map[string]string{"Token": token}, payload)
		if err != nil {
			return result, err
		}
		var response struct {
			Ret int `json:"ret"`
		}
		if json.Unmarshal(content, &response) != nil || status < 200 || status >= 300 || response.Ret != 0 {
			return result, fmt.Errorf("UniCloud certificate update failed (HTTP %d)", status)
		}
		result.Written = true
		if result.Location != "" {
			result.Location += ","
		}
		result.Location += domain
	}
	return result, nil
}

func rawURLEncode(value string) string { return strings.ReplaceAll(url.QueryEscape(value), "+", "%20") }

func (t *UniCloud) clientInfo(name string) uniClientInfo {
	const appID = "__UNI__unicloud_console"
	const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36"
	return uniClientInfo{Platform: "web", OS: "windows", UpperAppID: appID, UpperDeviceID: t.deviceID, Scene: 1001,
		AppID: appID, AppLanguage: "zh-Hans", AppName: name, AppVersion: "1.0.0", AppVersionCode: "100",
		BrowserName: "chrome", BrowserVersion: "132.0.0.0", DeviceID: t.deviceID, DeviceModel: "PC", DeviceType: "pc",
		HostName: "chrome", HostVersion: "132.0.0.0", OSName: "windows", OSVersion: "10 x64", UA: ua,
		UniCompilerVersion: "5.23", UniPlatform: "web", UniRuntimeVersion: "5.23", Locale: "zh-Hans", UpperLocale: "zh-Hans"}
}

func (t *UniCloud) login(ctx context.Context) (string, error) {
	info := t.clientInfo("账号中心")
	challengeBiz := map[string]any{"functionTarget": "uni-id-co", "functionArgs": map[string]any{
		"method": "createPasswordChallenge", "params": []any{map[string]string{
			"action": "login", "resetAppId": "__UNI__unicloud_console", "resetUniPlatform": "web",
		}}, "clientInfo": info,
	}}
	data, err := t.invoke(ctx, "https://account.dcloud.net.cn/client", "uni-id-server", "ba461799-fde8-429f-8cc4-4b6d306e2339", info, challengeBiz, "")
	if err != nil {
		return "", err
	}
	var challenge uniChallenge
	if json.Unmarshal(data, &challenge) != nil {
		return "", errors.New("invalid UniCloud password challenge")
	}
	envelope, err := t.passwordEnvelope(challenge)
	if err != nil {
		return "", err
	}
	loginBiz := map[string]any{"functionTarget": "uni-id-co", "functionArgs": map[string]any{
		"method": "login", "params": []any{map[string]any{
			"captcha": "", "resetAppId": "__UNI__unicloud_console", "resetUniPlatform": "web", "isReturnToken": false,
			"passwordEnvelope": envelope,
		}}, "clientInfo": info,
	}}
	data, err = t.invoke(ctx, "https://account.dcloud.net.cn/client", "uni-id-server", "ba461799-fde8-429f-8cc4-4b6d306e2339", info, loginBiz, "")
	if err != nil {
		return "", err
	}
	var response struct {
		ErrCode  int `json:"errCode"`
		NewToken struct {
			Token string `json:"token"`
		} `json:"newToken"`
	}
	if json.Unmarshal(data, &response) != nil || response.ErrCode != 0 || response.NewToken.Token == "" {
		return "", errors.New("UniCloud account login failed")
	}
	return response.NewToken.Token, nil
}

func (t *UniCloud) passwordEnvelope(challenge uniChallenge) (uniEnvelope, error) {
	if challenge.Algorithm != "RSA-OAEP-256+A256GCM" || challenge.PublicKey == "" || challenge.ChallengeID == "" {
		return uniEnvelope{}, errors.New("unsupported UniCloud password challenge")
	}
	header := uniEnvelopeHeader{Version: challenge.Version, Algorithm: challenge.Algorithm, KeyID: challenge.KeyID, ChallengeID: challenge.ChallengeID}
	aad, err := json.Marshal(header)
	if err != nil {
		return uniEnvelope{}, errors.New("encode UniCloud envelope header failed")
	}
	payload, err := json.Marshal(struct {
		Action      string `json:"action"`
		ChallengeID string `json:"challengeId"`
		IssuedAt    int64  `json:"issuedAt"`
		Password    string `json:"password"`
		Email       string `json:"email"`
	}{Action: "login", ChallengeID: challenge.ChallengeID, IssuedAt: time.Now().UnixMilli(), Password: t.password, Email: t.username})
	if err != nil {
		return uniEnvelope{}, errors.New("encode UniCloud password payload failed")
	}
	var key [32]byte
	var iv [12]byte
	if _, err := rand.Read(key[:]); err != nil {
		return uniEnvelope{}, errors.New("UniCloud encryption random source failed")
	}
	if _, err := rand.Read(iv[:]); err != nil {
		return uniEnvelope{}, errors.New("UniCloud encryption random source failed")
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return uniEnvelope{}, errors.New("initialize UniCloud AES failed")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return uniEnvelope{}, errors.New("initialize UniCloud GCM failed")
	}
	sealed := aead.Seal(nil, iv[:], payload, aad)
	publicBlock, _ := pem.Decode([]byte(challenge.PublicKey))
	if publicBlock == nil {
		return uniEnvelope{}, errors.New("invalid UniCloud RSA public key")
	}
	var publicKey *rsa.PublicKey
	if parsed, err := x509.ParsePKIXPublicKey(publicBlock.Bytes); err == nil {
		publicKey, _ = parsed.(*rsa.PublicKey)
	}
	if publicKey == nil {
		publicKey, _ = x509.ParsePKCS1PublicKey(publicBlock.Bytes)
	}
	if publicKey == nil {
		return uniEnvelope{}, errors.New("invalid UniCloud RSA public key")
	}
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, key[:], nil)
	if err != nil {
		return uniEnvelope{}, errors.New("encrypt UniCloud AES key failed")
	}
	return uniEnvelope{Version: challenge.Version, Algorithm: challenge.Algorithm, KeyID: challenge.KeyID, ChallengeID: challenge.ChallengeID,
		EncryptedKey: base64.StdEncoding.EncodeToString(encryptedKey), IV: base64.StdEncoding.EncodeToString(iv[:]),
		Ciphertext: base64.StdEncoding.EncodeToString(sealed[:len(sealed)-16]), Tag: base64.StdEncoding.EncodeToString(sealed[len(sealed)-16:])}, nil
}

func (t *UniCloud) getToken(ctx context.Context) (string, error) {
	accountToken, err := t.login(ctx)
	if err != nil {
		return "", err
	}
	info := t.clientInfo("uniCloud控制台")
	biz := map[string]any{"functionTarget": "uni-cloud-kernel", "functionArgs": map[string]any{
		"action": "user/getUserToken", "data": map[string]bool{"isLogin": true}, "clientInfo": info, "uniIdToken": accountToken,
	}}
	data, err := t.invoke(ctx, "https://unicloud.dcloud.net.cn/client", "dc-6nfabcn6ada8d3dd", "4c1f7fbf-c732-42b0-ab10-4634a8bbe834", info, biz, accountToken)
	if err != nil {
		return "", err
	}
	var response struct {
		Code int `json:"code"`
		Data struct {
			Ret  int `json:"ret"`
			Data struct {
				Token string `json:"token"`
			} `json:"data"`
		} `json:"data"`
	}
	if json.Unmarshal(data, &response) != nil || response.Code != 0 || response.Data.Ret != 0 || response.Data.Data.Token == "" {
		return "", errors.New("UniCloud API token exchange failed")
	}
	return response.Data.Data.Token, nil
}

func (t *UniCloud) invoke(ctx context.Context, endpoint, spaceID, signKey string, info uniClientInfo, biz any, accountToken string) (json.RawMessage, error) {
	bizJSON, err := json.Marshal(biz)
	if err != nil {
		return nil, errors.New("encode UniCloud function arguments failed")
	}
	outer := map[string]any{"method": "serverless.function.runtime.invoke", "params": string(bizJSON), "spaceId": spaceID, "timestamp": time.Now().UnixMilli()}
	keys := []string{"method", "params", "spaceId", "timestamp"}
	sort.Strings(keys)
	var parts []string
	for _, key := range keys {
		parts = append(parts, key+"="+fmt.Sprint(outer[key]))
	}
	mac := hmac.New(md5.New, []byte(signKey))
	_, _ = mac.Write([]byte(strings.Join(parts, "&")))
	infoJSON, err := json.Marshal(info)
	if err != nil {
		return nil, errors.New("encode UniCloud client information failed")
	}
	headers := map[string]string{"Origin": "https://account.dcloud.net.cn", "Referer": "https://account.dcloud.net.cn/",
		"X-Client-Info": string(infoJSON), "X-Serverless-Sign": hex.EncodeToString(mac.Sum(nil))}
	if accountToken != "" {
		headers["X-Client-Token"] = accountToken
	}
	status, content, err := requestJSON(ctx, t.client, http.MethodPost, endpoint, headers, outer)
	if err != nil {
		return nil, err
	}
	var response struct {
		Success bool            `json:"success"`
		Data    json.RawMessage `json:"data"`
	}
	if json.Unmarshal(content, &response) != nil || status < 200 || status >= 300 || !response.Success || len(response.Data) == 0 {
		return nil, fmt.Errorf("UniCloud function invocation failed (HTTP %d)", status)
	}
	return response.Data, nil
}

var _ Target = (*UniCloud)(nil)
