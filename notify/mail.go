package notify

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rainchen537/dnsgo/internal/aliyunrpc"
)

type SMTP struct {
	Host     string
	Port     int
	User     string
	Password string
	From     string
	To       string
	FromName string
}

func (SMTP) Name() string { return "smtp" }
func (s SMTP) Send(ctx context.Context, e Event) error {
	if s.Host == "" || s.Port == 0 || s.From == "" || s.To == "" {
		return fmt.Errorf("SMTP host, port, from and to are required")
	}
	from, err := mail.ParseAddress(s.From)
	if err != nil || from.Address != s.From {
		return fmt.Errorf("invalid SMTP sender")
	}
	to, err := mail.ParseAddress(s.To)
	if err != nil || to.Address != s.To {
		return fmt.Errorf("invalid SMTP recipient")
	}
	address := net.JoinHostPort(s.Host, strconv.Itoa(s.Port))
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return fmt.Errorf("SMTP connection failed: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	secure := s.Port == 465
	if secure {
		wrapped := tls.Client(conn, &tls.Config{ServerName: s.Host, MinVersion: tls.VersionTLS12})
		if err := wrapped.HandshakeContext(ctx); err != nil {
			return fmt.Errorf("SMTP TLS handshake failed: %w", err)
		}
		conn = wrapped
	}
	client, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		return fmt.Errorf("SMTP handshake failed: %w", err)
	}
	defer client.Close()
	if !secure {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return fmt.Errorf("SMTP server does not support STARTTLS")
		}
		if err := client.StartTLS(&tls.Config{ServerName: s.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("SMTP STARTTLS failed: %w", err)
		}
	}
	if s.User != "" {
		if err := client.Auth(smtp.PlainAuth("", s.User, s.Password, s.Host)); err != nil {
			return fmt.Errorf("SMTP authentication failed")
		}
	}
	if err := client.Mail(from.Address); err != nil {
		return fmt.Errorf("SMTP sender rejected")
	}
	if err := client.Rcpt(to.Address); err != nil {
		return fmt.Errorf("SMTP recipient rejected")
	}
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("SMTP DATA rejected")
	}
	name := s.FromName
	if name == "" {
		name = "DnsGo"
	}
	message := "From: " + (&mail.Address{Name: name, Address: from.Address}).String() + "\r\n" +
		"To: " + to.Address + "\r\n" +
		"Subject: " + mime.QEncoding.Encode("utf-8", e.Title) + "\r\n" +
		"MIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n" + e.HTML
	if _, err := io.WriteString(writer, message); err != nil {
		_ = writer.Close()
		return fmt.Errorf("SMTP message write failed")
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("SMTP message rejected")
	}
	return client.Quit()
}

type SendCloud struct {
	APIUser, APIKey, From, To, FromName string
	Client                              *http.Client
}

func (SendCloud) Name() string { return "sendcloud" }
func (s SendCloud) Send(ctx context.Context, e Event) error {
	if s.APIUser == "" || s.APIKey == "" || s.From == "" || s.To == "" {
		return fmt.Errorf("SendCloud account, sender and recipient are required")
	}
	values := url.Values{"apiUser": {s.APIUser}, "apiKey": {s.APIKey}, "from": {s.From},
		"fromName": {s.FromName}, "to": {s.To}, "subject": {e.Title}, "html": {e.HTML}}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.sendcloud.net/apiv2/mail/send", strings.NewReader(values.Encode()))
	if err != nil {
		return fmt.Errorf("invalid SendCloud request")
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := httpClient(s.Client).Do(request)
	if err != nil {
		return fmt.Errorf("SendCloud request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return fmt.Errorf("SendCloud returned HTTP %d", response.StatusCode)
	}
	var result struct {
		StatusCode int      `json:"statusCode"`
		Message    []string `json:"message"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&result); err != nil {
		return fmt.Errorf("invalid SendCloud response")
	}
	if result.StatusCode != 200 {
		return fmt.Errorf("SendCloud rejected message: %s", strings.Join(result.Message, "; "))
	}
	return nil
}

type AliyunDirectMail struct {
	KeyID, Secret, From, To, FromName string
	Client                            *http.Client
}

func (AliyunDirectMail) Name() string { return "aliyun_directmail" }
func (a AliyunDirectMail) Send(ctx context.Context, e Event) error {
	if a.KeyID == "" || a.Secret == "" || a.From == "" || a.To == "" {
		return fmt.Errorf("Aliyun DirectMail account, sender and recipient are required")
	}
	client := aliyunrpc.Client{KeyID: a.KeyID, Secret: a.Secret, Endpoint: "https://dm.aliyuncs.com", Version: "2015-11-23", HTTP: a.Client}
	return client.Call(ctx, http.MethodPost, "SingleSendMail", url.Values{
		"AccountName": {a.From}, "ReplyToAddress": {"false"}, "AddressType": {"1"},
		"ToAddress": {a.To}, "FromAlias": {a.FromName}, "Subject": {e.Title}, "HtmlBody": {e.HTML},
	}, nil)
}
