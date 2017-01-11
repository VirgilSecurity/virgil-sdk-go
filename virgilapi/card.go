package virgilapi

import (
	"gopkg.in/virgil.v4"
	"gopkg.in/virgil.v4/virgilcrypto"
)

type Card struct {
	Context *Context
	Model   *virgil.Card
}

func (c *Card) Encrypt(data Buffer) (Buffer, error) {
	return c.Context.Crypto.Encrypt(data, c.Model.PublicKey)
}

func (c *Card) Verify(data Buffer, signature Buffer) (bool, error) {
	return c.Context.Crypto.Verify(data, signature, c.Model.PublicKey)
}

type cards []*Card

func (c cards) ToRecipients() []virgilcrypto.PublicKey {
	res := make([]virgilcrypto.PublicKey, len(c))
	for i, r := range c {
		res[i] = r.Model.PublicKey
	}
	return res
}

func (c cards) Encrypt(data Buffer, context *Context) (Buffer, error) {
	return context.Crypto.Encrypt(data, c.ToRecipients()...)
}

func (c cards) SignThenEncrypt(data Buffer, signerKey *Key, context *Context) (Buffer, error) {
	return context.Crypto.SignThenEncrypt(data, signerKey.PrivateKey, c.ToRecipients()...)
}
