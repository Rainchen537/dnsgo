package agent

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// proxyHTTPClient constructs a client for the optional resident program.
// SDK callers can supply their own HTTPClient to each provider or target.
func proxyHTTPClient(raw string) (*http.Client, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" || parsed.Port() == "" || parsed.Path != "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("invalid proxy URL")
	}
	if port, err := strconv.Atoi(parsed.Port()); err != nil || port < 1 || port > 65535 {
		return nil, errors.New("invalid proxy port")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https", "socks5", "socks5h":
		transport.Proxy = http.ProxyURL(parsed)
	case "socks4":
		user := ""
		if parsed.User != nil {
			user = parsed.User.Username()
			if _, hasPassword := parsed.User.Password(); hasPassword {
				return nil, errors.New("SOCKS4 does not support a proxy password")
			}
		}
		if strings.ContainsRune(user, '\x00') {
			return nil, errors.New("invalid SOCKS4 user")
		}
		transport.Proxy = nil
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialSOCKS4(ctx, net.JoinHostPort(parsed.Hostname(), parsed.Port()), user, address)
		}
	default:
		return nil, errors.New("unsupported proxy scheme")
	}
	return &http.Client{Transport: transport, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

func dialSOCKS4(ctx context.Context, proxyAddress, user, destination string) (net.Conn, error) {
	host, portText, err := net.SplitHostPort(destination)
	if err != nil {
		return nil, errors.New("invalid SOCKS4 destination")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("invalid SOCKS4 destination port")
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		addresses, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
		if err != nil || len(addresses) == 0 {
			return nil, errors.New("SOCKS4 destination has no IPv4 address")
		}
		ip = addresses[0].To4()
	}
	if ip == nil {
		return nil, errors.New("SOCKS4 destination has no IPv4 address")
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxyAddress)
	if err != nil {
		return nil, errors.New("SOCKS4 proxy connection failed")
	}
	stopCancel := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stopCancel()
	closeOnError := func(err error) (net.Conn, error) {
		_ = connection.Close()
		return nil, err
	}
	deadline := time.Now().Add(30 * time.Second)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return closeOnError(err)
	}
	request := []byte{4, 1, byte(port >> 8), byte(port), ip[0], ip[1], ip[2], ip[3]}
	request = append(request, user...)
	request = append(request, 0)
	if _, err := io.Copy(connection, bytes.NewReader(request)); err != nil {
		return closeOnError(errors.New("SOCKS4 handshake failed"))
	}
	var response [8]byte
	if _, err := io.ReadFull(connection, response[:]); err != nil || response[0] != 0 || response[1] != 90 {
		return closeOnError(errors.New("SOCKS4 proxy refused the connection"))
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		return closeOnError(err)
	}
	return connection, nil
}
