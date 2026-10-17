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
)

// CustomWebhook supports the reference project's GET/POST and body template
// modes. HTTPS and normal TLS verification are always required.
type CustomWebhook struct {
	URL, Method, ContentType, Format, BodyTemplate string
	Headers                                        http.Header
	Client                                         *http.Client
}

func (CustomWebhook) Name() string { return "custom_webhook" }
func (w CustomWebhook) Send(ctx context.Context, e Event) error {
	parsed, err := url.Parse(w.URL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return fmt.Errorf("custom webhook requires HTTPS URL")
	}
	method := strings.ToUpper(w.Method)
	if method == "" {
		method = http.MethodPost
	}
	if method != http.MethodGet && method != http.MethodPost && method != http.MethodPut {
		return fmt.Errorf("unsupported custom webhook method")
	}
	contentType := w.ContentType
	if contentType == "" {
		contentType = "application/json"
	}
	content := e.HTML
	if w.Format != "html" {
		content = e.Text()
	}
	template := w.BodyTemplate
	if template == "" {
		template = `{"title":"{title}","content":"{content}"}`
	}
	var body string
	if strings.HasPrefix(contentType, "application/json") {
		// Replace placeholders as JSON string fragments, retaining the quotes
		// in the caller's template and escaping event content correctly.
		quote := func(value string) string {
			encoded, _ := json.Marshal(value)
			return string(encoded[1 : len(encoded)-1])
		}
		body = strings.NewReplacer("{title}", quote(e.Title), "{content}", quote(content)).Replace(template)
		if !json.Valid([]byte(body)) {
			fallback, _ := json.Marshal(map[string]string{"title": e.Title, "content": content})
			body = string(fallback)
		}
	} else {
		body = strings.NewReplacer("{title}", e.Title, "{content}", content).Replace(template)
	}
	var reader io.Reader
	if method == http.MethodGet {
		query := parsed.Query()
		if strings.HasPrefix(contentType, "application/json") {
			var fields map[string]any
			if err := json.Unmarshal([]byte(body), &fields); err != nil {
				return fmt.Errorf("invalid custom webhook GET parameters")
			}
			for key, value := range fields {
				query.Set(key, fmt.Sprint(value))
			}
		} else {
			fields, err := url.ParseQuery(body)
			if err != nil {
				return fmt.Errorf("invalid custom webhook GET parameters")
			}
			for key, values := range fields {
				for _, value := range values {
					query.Add(key, value)
				}
			}
		}
		parsed.RawQuery = query.Encode()
	} else {
		reader = bytes.NewBufferString(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, parsed.String(), reader)
	if err != nil {
		return fmt.Errorf("invalid custom webhook request")
	}
	for key, values := range w.Headers {
		for _, value := range values {
			request.Header.Add(key, value)
		}
	}
	if reader != nil {
		request.Header.Set("Content-Type", contentType)
	}
	response, err := httpClient(w.Client).Do(request)
	if err != nil {
		return fmt.Errorf("custom webhook request failed")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("custom webhook returned HTTP %d", response.StatusCode)
	}
	return nil
}
