package virgiljwt

import "errors"

var (
	ErrSignatureDecode    = errors.New("signature decoding error")
	ErrSignatureIsInvalid = errors.New("signature is invalid")
)
