package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

func httpClient(client *http.Client) *http.Client {
	if client != nil {
		return client
	}
	return &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

func post(ctx context.Context, client *http.Client, endpoint string, payload any, headers http.Header) (map[string]any, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return nil, fmt.Errorf("notification endpoint must be an HTTPS URL")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, parsed.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("invalid notification request")
	}
	request.Header.Set("Content-Type", "application/json")
	for key, values := range headers {
		for _, value := range values {
			request.Header.Add(key, value)
		}
	}
	response, err := httpClient(client).Do(request)
	if err != nil {
		// A URL may contain a bot token or webhook secret. net/http errors
		// often include the full URL, so do not return the raw error.
		return nil, fmt.Errorf("notification request failed")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("notification endpoint returned HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("notification response read failed")
	}
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("notification endpoint returned invalid JSON")
	}
	return result, nil
}

func stringResult(v any) string { return fmt.Sprint(v) }

type WXPusher struct {
	AppToken string
	UID      string
	Client   *http.Client
}

func (WXPusher) Name() string { return "wxpusher" }
func (w WXPusher) Send(ctx context.Context, e Event) error {
	if w.AppToken == "" || w.UID == "" {
		return fmt.Errorf("app token and UID are required")
	}
	r, err := post(ctx, w.Client, "https://wxpusher.zjiecode.com/api/send/message", map[string]any{
		"appToken": w.AppToken, "uids": []string{w.UID}, "summary": e.Title,
		"content": e.Text(), "contentType": 3,
	}, nil)
	if err != nil {
		return err
	}
	if r["success"] != true {
		return fmt.Errorf("WXPusher rejected message: %v", r["msg"])
	}
	return nil
}

type Telegram struct {
	Token, ChatID string
	TopicID       int64
	BaseURL       string
	Client        *http.Client
}

func (Telegram) Name() string { return "telegram" }
func (t Telegram) Send(ctx context.Context, e Event) error {
	if t.Token == "" || t.ChatID == "" {
		return fmt.Errorf("bot token and chat ID are required")
	}
	base := t.BaseURL
	if base == "" {
		base = "https://api.telegram.org"
	}
	payload := map[string]any{"chat_id": t.ChatID, "text": "<b>" + escapeTelegram(e.Title) + "</b>\n" + escapeTelegram(e.Text()), "parse_mode": "HTML"}
	if t.TopicID > 0 {
		payload["message_thread_id"] = t.TopicID
	}
	r, err := post(ctx, t.Client, strings.TrimRight(base, "/")+"/bot"+t.Token+"/sendMessage", payload, nil)
	if err != nil {
		return err
	}
	if r["ok"] != true {
		return fmt.Errorf("Telegram rejected message: %v", r["description"])
	}
	return nil
}

func escapeTelegram(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

type QQBot struct {
	AppID, AppSecret, OpenID string
	Client                   *http.Client
	mu                       sync.Mutex
	token                    string
	expires                  time.Time
}

func (*QQBot) Name() string { return "qqbot" }
func (q *QQBot) Send(ctx context.Context, e Event) error {
	if q == nil || q.AppID == "" || q.AppSecret == "" || q.OpenID == "" {
		return fmt.Errorf("QQ bot app ID, secret and open ID are required")
	}
	token, err := q.accessToken(ctx)
	if err != nil {
		return err
	}
	headers := http.Header{"Authorization": []string{"QQBot " + token}}
	r, err := post(ctx, q.Client, "https://api.bot.qq.com/v2/users/"+url.PathEscape(q.OpenID)+"/messages", map[string]any{
		"msg_type": 2, "markdown": map[string]string{"content": "# " + e.Title + "\n\n" + e.Text()},
	}, headers)
	if err != nil {
		return err
	}
	if stringResult(r["id"]) == "<nil>" || r["id"] == "" {
		return fmt.Errorf("QQ bot did not confirm delivery: %v", r["message"])
	}
	return nil
}

func (q *QQBot) accessToken(ctx context.Context) (string, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.token != "" && time.Now().Before(q.expires) {
		return q.token, nil
	}
	r, err := post(ctx, q.Client, "https://api.bot.qq.com/app/getAppAccessToken", map[string]string{
		"appId": q.AppID, "clientSecret": q.AppSecret,
	}, nil)
	if err != nil {
		return "", err
	}
	token, _ := r["access_token"].(string)
	if token == "" {
		return "", fmt.Errorf("QQ bot token request failed: %v", r["message"])
	}
	ttl := 7200.0
	if n, ok := r["expires_in"].(float64); ok && n > 0 {
		ttl = n
	}
	q.token = token
	q.expires = time.Now().Add(time.Duration(ttl-120) * time.Second)
	return token, nil
}

type Webhook struct {
	URL, AtUsers string
	Client       *http.Client
}

func (Webhook) Name() string { return "webhook" }
func (w Webhook) Send(ctx context.Context, e Event) error {
	parsed, err := url.Parse(w.URL)
	if err != nil || parsed.Scheme != "https" {
		return fmt.Errorf("webhook requires HTTPS URL")
	}
	host := strings.ToLower(parsed.Hostname())
	content := e.Text()
	var payload any
	switch host {
	case "oapi.dingtalk.com":
		payload = map[string]any{"msgtype": "markdown", "markdown": map[string]string{"title": e.Title, "text": "### " + e.Title + "\n" + content}}
		if w.AtUsers != "" {
			at := map[string]any{"isAtAll": w.AtUsers == "all"}
			if w.AtUsers != "all" {
				at["atMobiles"] = strings.Split(w.AtUsers, ",")
			}
			payload.(map[string]any)["at"] = at
		}
	case "qyapi.weixin.qq.com":
		payload = map[string]any{"msgtype": "markdown", "markdown": map[string]string{"content": "## " + e.Title + "\n" + content}}
	case "open.feishu.cn", "open.larksuite.com":
		cardContent := content
		if w.AtUsers == "all" {
			cardContent += "\n<at id=all></at>"
		} else if w.AtUsers != "" {
			for _, user := range strings.Split(w.AtUsers, ",") {
				cardContent += "\n<at user_id=\"" + strings.TrimSpace(user) + "\"></at>"
			}
		}
		template := "blue"
		if !e.Success {
			template = "red"
		} else if e.Kind == Expiry {
			template = "yellow"
		} else if e.Kind == Failover {
			template = "green"
		}
		payload = map[string]any{"msg_type": "interactive", "card": map[string]any{
			"schema": "2.0", "header": map[string]any{"title": map[string]string{"tag": "plain_text", "content": e.Title}, "template": template},
			"body": map[string]any{"elements": []any{map[string]string{"tag": "markdown", "content": cardContent}}},
		}}
	default:
		return fmt.Errorf("unsupported webhook host")
	}
	r, err := post(ctx, w.Client, w.URL, payload, nil)
	if err != nil {
		return err
	}
	if r["errcode"] != float64(0) && r["code"] != float64(0) {
		return fmt.Errorf("webhook rejected message: %v", r["errmsg"])
	}
	return nil
}
