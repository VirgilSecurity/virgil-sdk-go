package virgilapi

import (
	"io"

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

func (k *Key) DecryptStream(in io.Reader, out io.Writer) error {
		return virgil.Crypto().DecryptStream(in, out, k.privateKey)
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

func (k *Key) DecryptThenVerify(data Buffer, cards ...*Card) (Buffer, error) {

	keys := make([]virgilcrypto.PublicKey, 0, len(cards))
	for _, c := range cards {
		keys = append(keys, c.PublicKey)
	}

	return virgil.Crypto().DecryptThenVerify(data, k.privateKey, keys...)
}

func (k *Key) DecryptThenVerifyString(data string, cards ...*Card) (Buffer, error) {
	if buf, err := BufferFromBase64String(data); err != nil {
		return nil, err
	} else {
		keys := make([]virgilcrypto.PublicKey, 0, len(cards))
		for _, c := range cards {
			keys = append(keys, c.PublicKey)
		}
		return virgil.Crypto().DecryptThenVerify(buf, k.privateKey, keys...)
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
