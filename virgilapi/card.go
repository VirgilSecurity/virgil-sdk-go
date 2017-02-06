package virgilapi

import (
	"gopkg.in/virgil.v4"
	"gopkg.in/virgil.v4/errors"
	"gopkg.in/virgil.v4/virgilcrypto"
)

type Card struct {
	*virgil.Card
	Context *Context
}

func (c *Card) Encrypt(data Buffer) (Buffer, error) {
	if c == nil {
		return nil, errors.New("Card model is nil")
	}
	return virgil.Crypto().Encrypt(data, c.PublicKey)
}

func (c *Card) Verify(data Buffer, signature Buffer) (bool, error) {
	if c == nil {
		return false, errors.New("Card model is nil")
	}
	return virgil.Crypto().Verify(data, signature, c.PublicKey)
}

type cards []*Card

func (c cards) ToRecipients() []virgilcrypto.PublicKey {
	res := make([]virgilcrypto.PublicKey, len(c))
	for i, r := range c {
		res[i] = r.PublicKey
	}
	return res
}

func (c cards) Encrypt(data Buffer, context *Context) (Buffer, error) {
	return virgil.Crypto().Encrypt(data, c.ToRecipients()...)
}

func (c cards) SignThenEncrypt(data Buffer, signerKey *Key, context *Context) (Buffer, error) {
	return virgil.Crypto().SignThenEncrypt(data, signerKey.PrivateKey, c.ToRecipients()...)
}
