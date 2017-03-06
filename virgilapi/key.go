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

func (k *Key) SignString(data string) (Buffer, error) {
	return virgil.Crypto().Sign(BufferFromString(data), k.privateKey)
}

func (k *Key) Decrypt(data Buffer) (Buffer, error) {
	return virgil.Crypto().Decrypt(data, k.privateKey)
}

func (k *Key) DecryptString(data string) (Buffer, error) {

	if buf, err := BufferFromBase64String(data); err != nil {
		return nil, err
	} else {
		return virgil.Crypto().Decrypt(buf, k.privateKey)
	}

}

func (k *Key) SignThenEncrypt(data Buffer, recipients ...*Card) (Buffer, error) {
	return virgil.Crypto().SignThenEncrypt(data, k.privateKey, Cards(recipients).ToRecipients()...)
}

func (k *Key) SignThenEncryptString(data string, recipients ...*Card) (Buffer, error) {
	return virgil.Crypto().SignThenEncrypt(BufferFromString(data), k.privateKey, Cards(recipients).ToRecipients()...)
}

func (k *Key) DecryptThenVerify(data Buffer, card *Card) (Buffer, error) {
	return virgil.Crypto().DecryptThenVerify(data, k.privateKey, card.PublicKey)
}

func (k *Key) DecryptThenVerifyString(data string, card *Card) (Buffer, error) {
	if buf, err := BufferFromBase64String(data); err != nil {
		return nil, err
	} else {
		return virgil.Crypto().DecryptThenVerify(buf, k.privateKey, card.PublicKey)
	}

}

func (k *Key) ExportPublicKey() (Buffer, error) {

	pub, err := virgil.Crypto().ExtractPublicKey(k.privateKey)
	if err != nil {
		return nil, err
	}

	return virgil.Crypto().ExportPublicKey(pub)
}

func (k *Key) Save(alias string, password string) error {
	key, err := virgil.Crypto().ExportPrivateKey(k.privateKey, password)
	if err != nil {
		return err
	}
	item := &virgil.StorageItem{
		Data: key,
		Name: alias,
	}
	return k.context.storage.Store(item)
}
