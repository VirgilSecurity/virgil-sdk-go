// Package virgil is the pure Go implementation of Virgil Security compatible SDK
// Right now it supports only ed25519 keys and signatures and curve25519 key exchange
// As for symmetric crypto, it's AES256-GCM
// Hashes used are SHA-384 for signature and SHA-256 for fingerprints
package virgil

import (
	"gopkg.in/virgil.v4/virgilcrypto"
)

//Crypto returns a new instance of virgilcrypto with a default cipher
func Crypto() virgilcrypto.Crypto {
	return virgilcrypto.DefaultCrypto
}
