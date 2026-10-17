package automation

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestHTTPProbeProxyUsesDirectIPAndOriginalHost(t *testing.T) {
	seen := make(chan struct {
		ConnectTarget string
		Host          string
	}, 1)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		connection, stream, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer connection.Close()
		_, _ = fmt.Fprint(stream, "HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = stream.Flush()
		inner, err := http.ReadRequest(stream.Reader)
		if err != nil {
			return
		}
		seen <- struct {
			ConnectTarget string
			Host          string
		}{ConnectTarget: r.Host, Host: inner.Host}
		_, _ = fmt.Fprint(stream, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
		_ = stream.Flush()
	}))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyURL(proxyURL)
	defer transport.CloseIdleConnections()
	probe := Probe(context.Background(), ProbeConfig{Kind: ProbeHTTP, Target: "http://origin.invalid/health",
		IP: "127.0.0.1", ProxyURL: proxy.URL, HTTPClient: &http.Client{Transport: transport}, Timeout: 3 * time.Second})
	if !probe.Healthy {
		t.Fatalf("proxied direct-IP probe failed: %s", probe.Reason)
	}
	request := <-seen
	if request.ConnectTarget != "127.0.0.1:80" || request.Host != "origin.invalid" {
		t.Fatalf("proxy tunnel target %q and origin Host %q", request.ConnectTarget, request.Host)
	}
}

func TestHTTPSProbeProxyPreservesOriginTLSName(t *testing.T) {
	serverName := make(chan string, 1)
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverName <- r.TLS.ServerName
		w.WriteHeader(http.StatusOK)
	}))
	defer origin.Close()
	_, port, err := net.SplitHostPort(origin.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstream, err := net.Dial("tcp", origin.Listener.Addr().String())
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer upstream.Close()
		connection, stream, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer connection.Close()
		_, _ = fmt.Fprint(stream, "HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = stream.Flush()
		go io.Copy(upstream, stream)
		_, _ = io.Copy(connection, upstream)
	}))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyURL(proxyURL)
	defer transport.CloseIdleConnections()
	result := Probe(context.Background(), ProbeConfig{Kind: ProbeHTTP, Target: "https://origin.invalid:" + port + "/health",
		IP: "127.0.0.1", ProxyURL: proxy.URL, HTTPClient: &http.Client{Transport: transport},
		InsecureSkipVerify: true, Timeout: 3 * time.Second})
	if !result.Healthy {
		t.Fatalf("HTTPS proxy tunnel failed: %s", result.Reason)
	}
	select {
	case name := <-serverName:
		if name != "origin.invalid" {
			t.Fatalf("origin TLS SNI is %q", name)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("origin received no TLS request")
	}
}
