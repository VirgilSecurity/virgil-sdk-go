package virgilapi

import (
	"encoding/base64"
	"encoding/json"
	"io"

	"encoding/hex"

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

func (c *Card) EncryptStream(in io.Reader, out io.Writer) error{
	return virgil.Crypto().EncryptStream(in, out, c.PublicKey)
}

func (c *Card) encrypt(data Buffer) (Buffer, error) {
	return virgil.Crypto().Encrypt(data, c.PublicKey)
}

func (c *Card) Verify(data Buffer, signature Buffer) (bool, error) {
	return virgil.Crypto().Verify(data, signature, c.PublicKey)
}

func (c *Card) VerifyString(data string, signature string) (bool, error) {

	sign, err := BufferFromBase64String(signature)
	if err != nil {
		return false, err
	}

	return virgil.Crypto().Verify(BufferFromString(data), sign, c.PublicKey)
}

func (c *Card) Export() (string, error) {

	resp := &virgil.CardResponse{
		ID:       hex.EncodeToString(virgil.Crypto().CalculateFingerprint(c.Snapshot)),
		Snapshot: c.Snapshot,
		Meta: virgil.ResponseMeta{
			CardVersion: c.CardVersion,
			CreatedAt:   c.CreatedAt,
			Relations:   c.Relations,
			Signatures:  c.Signatures,
		},
	}

	res, err := json.Marshal(resp)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(res), nil
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

func (c *Cards) EncryptStream(in io.Reader, out io.Writer) error{
	return virgil.Crypto().EncryptStream(in, out, c.ToRecipients()...)
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
