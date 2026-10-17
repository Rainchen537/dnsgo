package providers

import "net/http"

// ambiguousWriteResponse marks an HTTP timeout or server failure after a
// mutating request. The provider may have applied the change before replying.
func ambiguousWriteResponse(method string, status int) bool {
	return method != http.MethodGet && (status == http.StatusRequestTimeout || status >= http.StatusInternalServerError)
}
