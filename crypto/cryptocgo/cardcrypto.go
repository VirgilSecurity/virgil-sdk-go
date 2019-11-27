package cryptocgo

import (
	"crypto/sha512"

	"github.com/VirgilSecurity/virgil-sdk-go/crypto"
)

type CardCrypto struct {
	Crypto *cryptoCgo
}

func NewVirgilCardCrypto() *CardCrypto {
	return &CardCrypto{Crypto: NewVirgilCrypto()}
}

func (c *CardCrypto) GenerateSignature(data []byte, key crypto.PrivateKey) ([]byte, error) {
	return c.Crypto.Sign(data, key)
}

func (c *CardCrypto) VerifySignature(data []byte, signature []byte, key crypto.PublicKey) error {
	return c.Crypto.VerifySignature(data, signature, key)
}

func (c *CardCrypto) ExportPublicKey(key crypto.PublicKey) ([]byte, error) {
	return c.Crypto.ExportPublicKey(key)
}

func (c *CardCrypto) ImportPublicKey(data []byte) (crypto.PublicKey, error) {
	return c.Crypto.ImportPublicKey(data)
}

func (c *CardCrypto) GenerateSHA512(data []byte) []byte {
	hash := sha512.Sum512(data)
	return hash[:]
}
