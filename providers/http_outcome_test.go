package providers

import (
	"net/http"
	"testing"
)

func TestAmbiguousWriteResponse(t *testing.T) {
	for _, status := range []int{http.StatusRequestTimeout, http.StatusInternalServerError, http.StatusBadGateway} {
		if !ambiguousWriteResponse(http.MethodPost, status) || !ambiguousWriteResponse(http.MethodDelete, status) {
			t.Errorf("write status %d should require readback", status)
		}
		if ambiguousWriteResponse(http.MethodGet, status) {
			t.Errorf("GET status %d should remain a read error", status)
		}
	}
	if ambiguousWriteResponse(http.MethodPost, http.StatusBadRequest) || ambiguousWriteResponse(http.MethodPost, http.StatusTooManyRequests) {
		t.Fatal("confirmed rejection was treated as an ambiguous write")
	}
}
