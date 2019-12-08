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

func (k publicKey) Export() ([]byte, error) {
	kp := foundation.NewKeyProvider()
	defer delete(kp)

	kp.SetRandom(random)
	if err := kp.SetupDefaults(); err != nil {
		return nil, err
	}

	return kp.ExportPublicKey(k.key)
}
