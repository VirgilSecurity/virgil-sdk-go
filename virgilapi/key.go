package virgilapi

import (
	"gopkg.in/virgil.v4"
	"gopkg.in/virgil.v4/virgilcrypto"
)

type Key struct {
	context    *Context
	privateKey virgilcrypto.PrivateKey
}

func (k *Key) Export(password string) (Buffer, error) {
	return virgil.Crypto().ExportPrivateKey(k.privateKey, password)
}

func (k *Key) Sign(data Buffer) (Buffer, error) {
	return virgil.Crypto().Sign(data, k.privateKey)
}

func (k *Key) Decrypt(data Buffer) (Buffer, error) {
	return virgil.Crypto().Sign(data, k.privateKey)
}

func (k *Key) SignThenEncrypt(data Buffer, recipients ...*Card) (Buffer, error) {
	return virgil.Crypto().SignThenEncrypt(data, k.privateKey, cards(recipients).ToRecipients()...)
}

func (k *Key) DecryptThenVerify(data Buffer, card *Card) (Buffer, error) {
	return virgil.Crypto().DecryptThenVerify(data, k.privateKey, card.PublicKey)
}

func (k *Key) Save(name string, password string) error {

	data, err := virgil.Crypto().ExportPrivateKey(k.privateKey, password)
	if err != nil {
		return err
	}

	item := &virgil.StorageItem{
		Name: name,
		Data: data,
	}

	return k.context.storage.Store(item)
}

func (k *Key) ExportPublicKey() (Buffer, error) {

	pub, err := virgil.Crypto().ExtractPublicKey(k.privateKey)
	if err != nil {
		return nil, err
	}

	return virgil.Crypto().ExportPublicKey(pub)
}
