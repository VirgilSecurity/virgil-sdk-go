package cryptocgo

import (
	"github.com/VirgilSecurity/virgil-sdk-go/crypto/cryptocgo/internal/foundation"
)

type publicKey struct {
	receiverID []byte
	key        foundation.PublicKey
}

func (k publicKey) Identifier() []byte {
	return k.receiverID
}

func (k publicKey) IsPublic() bool {
	return true
}
