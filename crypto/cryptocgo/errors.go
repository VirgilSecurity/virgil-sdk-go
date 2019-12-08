package cryptocgo

import (
	"errors"
	"fmt"

	"github.com/VirgilSecurity/virgil-sdk-go/crypto/cryptocgo/internal/foundation"
)

// crypto errors
var (
	ErrUnsupportedKeyType  = errors.New("unsupported key types")
	ErrUnsupportedHashType = errors.New("unsupported hash types")
	ErrStreamSizeIncorrect = errors.New("stream size should be greater 0")
	ErrInvalidSeedSize     = fmt.Errorf("invalid seed size (expected %d < x < %d)",
		foundation.KeyMaterialRngKeyMaterialLenMin,
		foundation.KeyMaterialRngKeyMaterialLenMax,
	)
	ErrUnsupportedParameter = errors.New("unsupported function parameter")
	ErrSignVerification     = errors.New("sign verification failed")
	ErrSignNotFound         = errors.New("signature not found")
)
