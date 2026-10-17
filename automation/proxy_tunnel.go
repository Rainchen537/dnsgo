package automation

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/url"
	"time"
)

type bufferedProxyConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedProxyConn) Read(data []byte) (int, error) { return c.reader.Read(data) }

// dialHTTPProxyTunnel uses CONNECT for both HTTP and HTTPS targets. A normal
// HTTP proxy request would replace the original Host with the IP authority.
func dialHTTPProxyTunnel(ctx context.Context, proxyURL *url.URL, target string, timeout time.Duration) (net.Conn, error) {
	if proxyURL == nil || proxyURL.Hostname() == "" || proxyURL.Port() == "" {
		return nil, errors.New("HTTP proxy host and port are required")
	}
	address := net.JoinHostPort(proxyURL.Hostname(), proxyURL.Port())
	dialer := &net.Dialer{Timeout: timeout}
	var connection net.Conn
	var err error
	if proxyURL.Scheme == "https" {
		connection, err = (&tls.Dialer{NetDialer: dialer, Config: &tls.Config{ServerName: proxyURL.Hostname()}}).DialContext(ctx, "tcp", address)
	} else {
		connection, err = dialer.DialContext(ctx, "tcp", address)
	}
	if err != nil {
		return nil, errors.New("HTTP proxy connection failed")
	}
	stopCancel := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stopCancel()
	closeOnError := func(err error) (net.Conn, error) {
		_ = connection.Close()
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return closeOnError(err)
	}
	request := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: target}, Host: target, Header: http.Header{}}
	if proxyURL.User != nil {
		password, _ := proxyURL.User.Password()
		auth := base64.StdEncoding.EncodeToString([]byte(proxyURL.User.Username() + ":" + password))
		request.Header.Set("Proxy-Authorization", "Basic "+auth)
	}
	if err := request.Write(connection); err != nil {
		return closeOnError(errors.New("HTTP proxy tunnel request failed"))
	}
	reader := bufio.NewReader(connection)
	response, err := http.ReadResponse(reader, request)
	if err != nil || response.StatusCode != http.StatusOK {
		return closeOnError(errors.New("HTTP proxy tunnel was refused"))
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		return closeOnError(err)
	}
	return &bufferedProxyConn{Conn: connection, reader: reader}, nil
}
