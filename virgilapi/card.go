package virgilapi

import (
	"encoding/base64"
	"encoding/json"

	"encoding/hex"

	"gopkg.in/virgil.v4"
	"gopkg.in/virgil.v4/errors"
	"gopkg.in/virgil.v4/virgilcrypto"
)

type Card struct {
	*virgil.Card
	context *Context
}

func (c *Card) Encrypt(data virgil.Buffer) (virgil.Buffer, error) {
	return virgil.Crypto().Encrypt(data, c.PublicKey)
}

func (c *Card) EncryptString(data string) (virgil.Buffer, error) {
	return c.encrypt(virgil.BufferFromString(data))
}

func (c *Card) encrypt(data virgil.Buffer) (virgil.Buffer, error) {
	return virgil.Crypto().Encrypt(data, c.PublicKey)
}

func (c *Card) Verify(data virgil.Buffer, signature virgil.Buffer) error {
	return virgil.Crypto().Verify(data, signature, c.PublicKey)
}

func (c *Card) VerifyString(data string, signature string) error {

	sign, err := virgil.BufferFromBase64String(signature)
	if err != nil {
		return err
	}

	return virgil.Crypto().Verify(virgil.BufferFromString(data), sign, c.PublicKey)
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

func (c Cards) Encrypt(data virgil.Buffer) (virgil.Buffer, error) {
	return virgil.Crypto().Encrypt(data, c.ToRecipients()...)
}

func (c Cards) EncryptString(data string) (virgil.Buffer, error) {
	return virgil.Crypto().Encrypt(virgil.BufferFromString(data), c.ToRecipients()...)
}

func (c Cards) SignThenEncrypt(data virgil.Buffer, signerKey *Key) (virgil.Buffer, error) {
	if signerKey == nil || signerKey.privateKey == nil || signerKey.privateKey.Empty() {
		return nil, errors.New("nil key")
	}
	return virgil.Crypto().SignThenEncrypt(data, signerKey.privateKey, c.ToRecipients()...)
}

func (c Cards) SignThenEncryptString(data string, signerKey *Key) (virgil.Buffer, error) {
	if signerKey == nil || signerKey.privateKey == nil || signerKey.privateKey.Empty() {
		return nil, errors.New("nil key")
	}
	return virgil.Crypto().SignThenEncrypt(virgil.BufferFromString(data), signerKey.privateKey, c.ToRecipients()...)
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

	resp, err := c.context.identityClient.VerifyIdentity(req)
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
