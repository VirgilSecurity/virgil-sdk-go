package common

import "fmt"

var (
	EntityNotFoundErr = VirgilAPIError{
		Message: "Entity was not found",
	}
)

type VirgilAPIError struct {
	Code    int
	Message string
}

func (err VirgilAPIError) Error() string {
	return fmt.Sprintf("Virgil API error {code: %v message: %v}", err.Code, err.Message)
}
