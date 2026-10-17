package deploy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rainchen537/dnsgo"
)

func TestWriteHTTPTimeoutNeedsReadback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusRequestTimeout)
	}))
	defer server.Close()
	_, _, err := request(context.Background(), server.Client(), http.MethodPost, server.URL, nil, nil)
	if !dnsgo.IsCode(err, dnsgo.CodeResultUnknown) {
		t.Fatalf("HTTP 408 after a write should require readback: %v", err)
	}
	status, _, err := request(context.Background(), server.Client(), http.MethodGet, server.URL, nil, nil)
	if err != nil || status != http.StatusRequestTimeout {
		t.Fatalf("GET 408 should remain a read response: %d, %v", status, err)
	}
}
