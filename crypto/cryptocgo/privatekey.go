package cryptocgo

import (
	"fmt"

	"github.com/VirgilSecurity/virgil-sdk-go/crypto"

	"github.com/VirgilSecurity/virgil-sdk-go/crypto/cryptocgo/internal/foundation"
)

type privateKey struct {
	receiverID []byte
	key        foundation.PrivateKey
}

func (k privateKey) Identifier() []byte {
	return k.receiverID
}

func (k privateKey) PublicKey() crypto.PublicKey {
	pk, err := k.key.ExtractPublicKey()
	if err != nil {
		panic(fmt.Errorf("PrivateKey.PublicKey: unexpected error: %v", err))
	}

	return publicKey{k.Identifier(), pk}
}
