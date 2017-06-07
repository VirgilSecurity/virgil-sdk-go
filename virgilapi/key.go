package virgilapi

import (
	"gopkg.in/virgil.v4"
	"gopkg.in/virgil.v4/virgilcrypto"
)

type Key struct {
	context    *Context
	privateKey virgilcrypto.PrivateKey
}

func (k *Key) Export(password string) (virgil.Buffer, error) {
	return virgil.Crypto().ExportPrivateKey(k.privateKey, password)
}

func (k *Key) Sign(data virgil.Buffer) (virgil.Buffer, error) {
	return virgil.Crypto().Sign(data, k.privateKey)
}

func (k *Key) SignString(data string) (virgil.Buffer, error) {
	return virgil.Crypto().Sign(virgil.BufferFromString(data), k.privateKey)
}

func (k *Key) Decrypt(data virgil.Buffer) (virgil.Buffer, error) {
	return virgil.Crypto().Decrypt(data, k.privateKey)
}

func (k *Key) DecryptString(data string) (virgil.Buffer, error) {

	if buf, err := virgil.BufferFromBase64String(data); err != nil {
		return nil, err
	} else {
		return virgil.Crypto().Decrypt(buf, k.privateKey)
	}

}

func (k *Key) SignThenEncrypt(data virgil.Buffer, recipients ...*Card) (virgil.Buffer, error) {
	return virgil.Crypto().SignThenEncrypt(data, k.privateKey, Cards(recipients).ToRecipients()...)
}

func (k *Key) SignThenEncryptString(data string, recipients ...*Card) (virgil.Buffer, error) {
	return virgil.Crypto().SignThenEncrypt(virgil.BufferFromString(data), k.privateKey, Cards(recipients).ToRecipients()...)
}

func (k *Key) DecryptThenVerify(data virgil.Buffer, cards ...*Card) (virgil.Buffer, error) {

	keys := make([]virgilcrypto.PublicKey, 0, len(cards))
	for _, c := range cards {
		keys = append(keys, c.PublicKey)
	}

	return virgil.Crypto().DecryptThenVerify(data, k.privateKey, keys...)
}

func (k *Key) DecryptThenVerifyString(data string, cards ...*Card) (virgil.Buffer, error) {
	if buf, err := virgil.BufferFromBase64String(data); err != nil {
		return nil, err
	} else {
		keys := make([]virgilcrypto.PublicKey, 0, len(cards))
		for _, c := range cards {
			keys = append(keys, c.PublicKey)
		}
		return virgil.Crypto().DecryptThenVerify(buf, k.privateKey, keys...)
	}

}

func (k *Key) ExportPublicKey() (virgil.Buffer, error) {

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
