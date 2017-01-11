package virgilapi

import (
	"gopkg.in/virgil.v4"
	"gopkg.in/virgil.v4/virgilcrypto"
)

type Key struct {
	Context    Context
	PrivateKey virgilcrypto.PrivateKey
}

func (k *Key) Export(password string) (Buffer, error) {
	return k.Context.Crypto.ExportPrivateKey(k.PrivateKey, password)
}

func (k *Key) Sign(data Buffer) (Buffer, error) {
	return k.Context.Crypto.Sign(data, k.PrivateKey)
}

func (k *Key) Decrypt(data Buffer) (Buffer, error) {
	return k.Context.Crypto.Sign(data, k.PrivateKey)
}

func (k *Key) SignThenEncrypt(data Buffer, recipients ...*Card) (Buffer, error) {
	return k.Context.Crypto.SignThenEncrypt(data, k.PrivateKey, cards(recipients).ToRecipients()...)
}

func (k *Key) DecryptThenVerify(data Buffer, card *Card) (Buffer, error) {
	return k.Context.Crypto.DecryptThenVerify(data, k.PrivateKey, card.Model.PublicKey)
}

func (k *Key) Save(name string, password string) error {

	data, err := k.Context.Crypto.ExportPrivateKey(k.PrivateKey, password)
	if err != nil {
		return err
	}

	item := &virgil.StorageItem{
		Name: name,
		Data: data,
	}

	return k.Context.Storage.Store(item)
}

func (k *Key) ExportPublicKey() (Buffer, error) {

	pub, err := k.Context.Crypto.ExtractPublicKey(k.PrivateKey)
	if err != nil {
		return nil, err
	}

	return k.Context.Crypto.ExportPublicKey(pub)
}
