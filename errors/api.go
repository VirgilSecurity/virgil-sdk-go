package errors

import (
	"errors"
	"fmt"
)

var (
	// ErrEntityNotFound return when service return 404 HTTP status code and body is empty
	ErrEntityNotFound = &VirgilAPIError{
		Code:    10001,
		Message: "entity was not found",
	}

	// ErrInternalServerError return when service return 5xx HTTP status code and body is empty
	ErrInternalServerError = &VirgilAPIError{
		Code:    10000,
		Message: "internal server error",
	}
)

// VirgilAPIError is service's errors
type VirgilAPIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (err *VirgilAPIError) Error() string {
	return fmt.Sprintf("Virgil API error {code: %v message: %v}", err.Code, err.Message)
}

func (err *VirgilAPIError) Is(e error) bool {
	var ve *VirgilAPIError
	if !errors.As(e, &ve) {
		return false
	}
	return ve.Code == err.Code
}
