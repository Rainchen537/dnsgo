package dnsgo

import (
	"errors"
	"fmt"
)

type ErrorCode string

const (
	CodeUnsupported    ErrorCode = "unsupported"
	CodeInvalidInput   ErrorCode = "invalid_input"
	CodeAuthentication ErrorCode = "authentication_failed"
	CodePermission     ErrorCode = "permission_denied"
	CodeRateLimited    ErrorCode = "rate_limited"
	CodeConflict       ErrorCode = "conflict"
	CodeNotFound       ErrorCode = "not_found"
	CodeTransport      ErrorCode = "transport_error"
	CodeResultUnknown  ErrorCode = "result_unknown"
	CodeProvider       ErrorCode = "provider_error"
)

// Error preserves a safe provider code and request ID without requiring
// callers to parse human-readable messages. Raw credentials must not be stored.
type Error struct {
	Provider   string
	Operation  string
	Code       ErrorCode
	VendorCode string
	RequestID  string
	Message    string
	Cause      error
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Message != "" {
		return fmt.Sprintf("%s %s: %s", e.Provider, e.Operation, e.Message)
	}
	return fmt.Sprintf("%s %s: %s", e.Provider, e.Operation, e.Code)
}

func (e *Error) Unwrap() error { return e.Cause }

func IsCode(err error, code ErrorCode) bool {
	var providerError *Error
	return errors.As(err, &providerError) && providerError.Code == code
}

func Unsupported(provider, operation string) error {
	return &Error{Provider: provider, Operation: operation, Code: CodeUnsupported}
}
