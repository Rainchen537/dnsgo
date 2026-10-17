package agent

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestProxyURLValidation(t *testing.T) {
	for _, address := range []string{
		"http://127.0.0.1:8080", "https://127.0.0.1:8443", "socks5://127.0.0.1:1080",
		"socks5h://127.0.0.1:1080", "socks4://user@127.0.0.1:1080",
	} {
		if _, err := proxyHTTPClient(address); err != nil {
			t.Errorf("valid proxy %s: %v", address, err)
		}
	}
	for _, address := range []string{"http://127.0.0.1", "socks4://user:password@127.0.0.1:1080", "ftp://127.0.0.1:21"} {
		if _, err := proxyHTTPClient(address); err == nil {
			t.Errorf("invalid proxy %s was accepted", address)
		}
	}
}

func TestSOCKS4Handshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	finished := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			finished <- err
			return
		}
		defer connection.Close()
		var header [8]byte
		_, err = io.ReadFull(connection, header[:])
		if err == nil && (header != [8]byte{4, 1, 1, 187, 127, 0, 0, 1}) {
			err = io.ErrUnexpectedEOF
		}
		if err == nil {
			var user [7]byte
			_, err = io.ReadFull(connection, user[:])
			if err == nil && string(user[:]) != "tester\x00" {
				err = io.ErrUnexpectedEOF
			}
		}
		if err == nil {
			_, err = connection.Write([]byte{0, 90, 0, 0, 0, 0, 0, 0})
		}
		finished <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, err := dialSOCKS4(ctx, listener.Addr().String(), "tester", "127.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	connection.Close()
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
}
