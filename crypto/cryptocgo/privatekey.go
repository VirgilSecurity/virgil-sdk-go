package cryptocgo

import (
	"github.com/VirgilSecurity/virgil-sdk-go/crypto/cryptocgo/internal/foundation"
)

type privateKey struct {
	receiverID []byte
	key        foundation.PrivateKey
}

func (k privateKey) Identifier() []byte {
	return k.receiverID
}

func (k privateKey) IsPrivate() bool {
	return true
}
