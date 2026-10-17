package agent

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/rainchen537/dnsgo"
)

// SafeError keeps diagnostic classification while omitting provider messages,
// URLs and nested errors that could contain keys, certificates or tokens.
func SafeError(err error) string {
	if err == nil {
		return ""
	}
	var providerError *dnsgo.Error
	if errors.As(err, &providerError) {
		result := fmt.Sprintf("%s %s: %s", providerError.Provider, providerError.Operation, providerError.Code)
		if safeErrorToken.MatchString(providerError.VendorCode) {
			result += " (vendor code " + providerError.VendorCode + ")"
		}
		if safeErrorToken.MatchString(providerError.RequestID) {
			result += " (request ID " + providerError.RequestID + ")"
		}
		return result
	}
	return "operation failed; inspect task state and provider status"
}

var safeErrorToken = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
