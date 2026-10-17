// Package automation provides reusable DNS failover and scheduling logic.
// The calling application owns task configuration and durable state.
package automation

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type ProbeKind string

const (
	ProbePing ProbeKind = "ping"
	ProbeTCP  ProbeKind = "tcp"
	ProbeHTTP ProbeKind = "http"
)

type ProbeConfig struct {
	Kind               ProbeKind
	Target             string // host or HTTP(S) URL
	IP                 string // optional direct target for TCP and HTTP(S)
	Port               int
	Timeout            time.Duration
	InsecureSkipVerify bool
	ProxyURL           string // set with an HTTPClient configured for this proxy
	HTTPClient         *http.Client
}

type ProbeResult struct {
	Healthy bool
	Latency time.Duration
	Reason  string
}

func Probe(ctx context.Context, config ProbeConfig) ProbeResult {
	if config.Timeout <= 0 {
		config.Timeout = 5 * time.Second
	}
	start := time.Now()
	var err error
	switch config.Kind {
	case ProbePing:
		err = probePing(ctx, config)
	case ProbeTCP:
		err = probeTCP(ctx, config)
	case ProbeHTTP:
		err = probeHTTP(ctx, config)
	default:
		err = fmt.Errorf("unknown probe kind")
	}
	result := ProbeResult{Healthy: err == nil, Latency: time.Since(start)}
	if err != nil {
		result.Reason = err.Error()
	}
	return result
}

func probePing(ctx context.Context, config ProbeConfig) error {
	target := config.Target
	if net.ParseIP(config.IP) != nil {
		target = config.IP
	}
	target = strings.TrimSuffix(target, ".")
	if target == "" {
		return fmt.Errorf("ping target is required")
	}
	ctx, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()
	args := []string{"-c", "1"}
	if net.ParseIP(target) != nil && strings.Contains(target, ":") {
		args = append(args, "-6")
	}
	if runtime.GOOS == "darwin" {
		args = append(args, "-W", strconv.Itoa(int(config.Timeout.Milliseconds())))
	} else if runtime.GOOS == "linux" {
		seconds := int((config.Timeout + time.Second - 1) / time.Second)
		args = append(args, "-W", strconv.Itoa(seconds))
	}
	args = append(args, target)
	command := exec.CommandContext(ctx, "ping", args...)
	_, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ping failed: %w", err)
	}
	return nil
}

func probeTCP(ctx context.Context, config ProbeConfig) error {
	if config.Port < 1 || config.Port > 65535 {
		return fmt.Errorf("valid TCP port is required")
	}
	target := config.Target
	if net.ParseIP(config.IP) != nil {
		target = config.IP
	}
	if target == "" {
		return fmt.Errorf("TCP target is required")
	}
	dialer := &net.Dialer{Timeout: config.Timeout}
	connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(strings.TrimSuffix(target, "."), strconv.Itoa(config.Port)))
	if err != nil {
		return fmt.Errorf("TCP connection failed: %w", err)
	}
	return connection.Close()
}

func probeHTTP(ctx context.Context, config ProbeConfig) error {
	parsed, err := url.Parse(config.Target)
	if err != nil || parsed.Host == "" || parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("valid HTTP(S) URL is required")
	}
	proxied := config.ProxyURL != ""
	var proxyURL *url.URL
	if proxied {
		proxyURL, err = url.Parse(config.ProxyURL)
		if err != nil || proxyURL.Hostname() == "" || proxyURL.Port() == "" || config.HTTPClient == nil {
			return fmt.Errorf("HTTP proxy URL and client are required together")
		}
		switch proxyURL.Scheme {
		case "http", "https", "socks4", "socks5", "socks5h":
		default:
			return fmt.Errorf("unsupported HTTP probe proxy scheme")
		}
	}
	tunnelProxy := proxied && config.IP != "" && (proxyURL.Scheme == "http" || proxyURL.Scheme == "https")
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{}
	}
	copyClient := *client
	if config.IP != "" {
		port := parsed.Port()
		if port == "" {
			port = "80"
			if parsed.Scheme == "https" {
				port = "443"
			}
		}
		copyClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many HTTP redirects")
			}
			redirectPort := req.URL.Port()
			if redirectPort == "" {
				redirectPort = "80"
				if req.URL.Scheme == "https" {
					redirectPort = "443"
				}
			}
			if req.URL.Scheme != parsed.Scheme || redirectPort != port ||
				!strings.EqualFold(req.URL.Hostname(), parsed.Hostname()) && req.URL.Hostname() != config.IP {
				return fmt.Errorf("HTTP redirect changed target host, scheme or port")
			}
			if proxied && !tunnelProxy {
				req.URL.Host = net.JoinHostPort(config.IP, port)
				req.Host = parsed.Host
			}
			return nil
		}
	}
	if copyClient.Timeout == 0 || copyClient.Timeout > config.Timeout {
		copyClient.Timeout = config.Timeout
	}
	if config.IP != "" || config.InsecureSkipVerify {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		if original, ok := client.Transport.(*http.Transport); ok {
			transport = original.Clone()
		} else if client.Transport != nil {
			return fmt.Errorf("HTTP IP override requires an http.Transport")
		}
		if config.IP != "" {
			if net.ParseIP(config.IP) == nil {
				return fmt.Errorf("HTTP direct target must be an IP address")
			}
			if !proxied {
				port := parsed.Port()
				if port == "" {
					port = "80"
					if parsed.Scheme == "https" {
						port = "443"
					}
				}
				transport.Proxy = nil
				dialer := &net.Dialer{Timeout: config.Timeout}
				transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
					return dialer.DialContext(ctx, network, net.JoinHostPort(config.IP, port))
				}
			} else if tunnelProxy {
				transport.Proxy = nil
				transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
					_, port, err := net.SplitHostPort(address)
					if err != nil {
						return nil, fmt.Errorf("invalid HTTP probe destination")
					}
					return dialHTTPProxyTunnel(ctx, proxyURL, net.JoinHostPort(config.IP, port), config.Timeout)
				}
			} else if parsed.Scheme == "https" {
				tlsConfig := &tls.Config{}
				if transport.TLSClientConfig != nil {
					tlsConfig = transport.TLSClientConfig.Clone()
				}
				tlsConfig.ServerName = parsed.Hostname()
				transport.TLSClientConfig = tlsConfig
			}
		}
		if config.InsecureSkipVerify {
			tlsConfig := &tls.Config{}
			if transport.TLSClientConfig != nil {
				tlsConfig = transport.TLSClientConfig.Clone()
			}
			tlsConfig.InsecureSkipVerify = true
			transport.TLSClientConfig = tlsConfig
		}
		copyClient.Transport = transport
		defer transport.CloseIdleConnections()
	}
	requestURL := *parsed
	if config.IP != "" && proxied && !tunnelProxy {
		port := parsed.Port()
		if port == "" {
			port = "80"
			if parsed.Scheme == "https" {
				port = "443"
			}
		}
		requestURL.Host = net.JoinHostPort(config.IP, port)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return fmt.Errorf("invalid HTTP request")
	}
	if config.IP != "" && proxied && !tunnelProxy {
		req.Host = parsed.Host
	}
	req.Header.Set("User-Agent", "DnsGo/1")
	response, err := copyClient.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request failed")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 400 {
		return fmt.Errorf("HTTP status %d", response.StatusCode)
	}
	return nil
}
