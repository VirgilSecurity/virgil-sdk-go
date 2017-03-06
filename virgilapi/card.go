package virgilapi

import (
	"encoding/base64"
	"encoding/json"

	"gopkg.in/virgil.v4"
	"gopkg.in/virgil.v4/errors"
	"gopkg.in/virgil.v4/virgilcrypto"
)

type Card struct {
	*virgil.Card
	context *Context
}

func (c *Card) Encrypt(data Buffer) (Buffer, error) {
	return virgil.Crypto().Encrypt(data, c.PublicKey)
}

func (c *Card) EncryptString(data string) (Buffer, error) {
	return c.encrypt(BufferFromString(data))
}

func (c *Card) encrypt(data Buffer) (Buffer, error) {
	return virgil.Crypto().Encrypt(data, c.PublicKey)
}

func (c *Card) Verify(data Buffer, signature Buffer) (bool, error) {
	return virgil.Crypto().Verify(data, signature, c.PublicKey)
}

func (c *Card) VerifyString(data string, signature Buffer) (bool, error) {
	return virgil.Crypto().Verify(BufferFromString(data), signature, c.PublicKey)
}

func (c *Card) Export() (string, error) {
	req, err := c.ToRequest()
	if err != nil {
		return "", err
	}
	data, err := req.Export()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

type Cards []*Card

func (c Cards) ToRecipients() []virgilcrypto.PublicKey {
	res := make([]virgilcrypto.PublicKey, len(c))
	for i, r := range c {
		res[i] = r.PublicKey
	}
	return res
}

func (c Cards) Encrypt(data Buffer) (Buffer, error) {
	return virgil.Crypto().Encrypt(data, c.ToRecipients()...)
}

func (c Cards) EncryptString(data string) (Buffer, error) {
	return virgil.Crypto().Encrypt(BufferFromString(data), c.ToRecipients()...)
}

func (c Cards) SignThenEncrypt(data Buffer, signerKey *Key) (Buffer, error) {
	if signerKey == nil || signerKey.privateKey == nil || signerKey.privateKey.Empty() {
		return nil, errors.New("nil key")
	}
	return virgil.Crypto().SignThenEncrypt(data, signerKey.privateKey, c.ToRecipients()...)
}

func (c Cards) SignThenEncryptString(data string, signerKey *Key) (Buffer, error) {
	if signerKey == nil || signerKey.privateKey == nil || signerKey.privateKey.Empty() {
		return nil, errors.New("nil key")
	}
	return virgil.Crypto().SignThenEncrypt(BufferFromString(data), signerKey.privateKey, c.ToRecipients()...)
}

func (c *Card) VerifyIdentity() (attempt *IdentityVerificationAttempt, err error) {

	createReq := &virgil.CardModel{}
	err = json.Unmarshal(c.Snapshot, createReq)
	if err != nil {
		return nil, errors.Wrap(err, "Cannot unwrap request snapshot")
	}

	req := &virgil.VerifyRequest{
		Type:  createReq.IdentityType,
		Value: createReq.Identity,
	}

	resp, err := c.context.client.VerifyIdentity(req)
	if err != nil {
		return nil, err
	}
	return &IdentityVerificationAttempt{
		context:     c.context,
		actionId:    resp.ActionId,
		TimeToLive:  3600,
		CountToLive: 1,
	}, nil
}
