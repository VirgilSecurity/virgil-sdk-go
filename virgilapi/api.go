package virgilapi

import (
	"gopkg.in/virgil.v4"
)

type Api struct {
	Context *Context
	Cards   CardManager
	Keys    KeyManager
}

func New(accessToken string) (*Api, error) {

	cli, err := virgil.NewClient(accessToken)
	if err != nil {
		return nil, err
	}
	context := &Context{
		Client:        cli,
		Crypto:        virgil.Crypto(),
		Storage:       &virgil.FileStorage{RootDir: "."},
		RequestSigner: &virgil.RequestSigner{},
	}

	return &Api{
		Context: context,
		Cards:   &cardManager{Context: context},
		Keys:    &keyManager{Context: context},
	}, nil
}

func (a *Api) Encrypt(data Buffer, recipients ...*Card) (Buffer, error) {
	return cards(recipients).Encrypt(data, a.Context)
}

func (a *Api) Decrypt(data Buffer, key *Key) (Buffer, error) {
	return key.Decrypt(data)
}

func (a *Api) Sign(data Buffer, key *Key) (Buffer, error) {
	return key.Sign(data)
}

func (a *Api) Verify(data Buffer, signature Buffer, signerCard *Card) (bool, error) {
	return signerCard.Verify(data, signature)
}

func (a *Api) SignThenEncrypt(data Buffer, signerKey *Key, recipients ...*Card) (Buffer, error) {
	return signerKey.SignThenEncrypt(data, recipients...)
}

func (a *Api) DecryptThenVerify(data Buffer, key *Key, signerCard *Card) (Buffer, error) {
	return key.DecryptThenVerify(data, signerCard)
}
