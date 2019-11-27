package cryptocgo

import "github.com/VirgilSecurity/virgil-sdk-go/crypto"

type keypair struct {
	publicKey  publicKey
	privateKey privateKey
}

func (e *keypair) HasPublic() bool {
	return true
}
func (e *keypair) HasPrivate() bool {
	return true
}
func (e *keypair) PublicKey() crypto.PublicKey {
	return e.publicKey
}
func (e *keypair) PrivateKey() crypto.PrivateKey {
	return e.privateKey
}
