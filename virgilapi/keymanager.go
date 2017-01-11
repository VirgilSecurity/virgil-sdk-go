package virgilapi

import (
	"gopkg.in/virgil.v4"
	"gopkg.in/virgil.v4/virgilcrypto"
)

type KeyManager interface {
	Generate() (virgilcrypto.PrivateKey, error)
	Store(keypair virgilcrypto.PrivateKey, alias string, password string) error
	Load(alias string, password string) (virgilcrypto.PrivateKey, error)
}

type keyManager struct {
	Context *Context
}

func (k *keyManager) Generate() (virgilcrypto.PrivateKey, error) {
	key, err := k.Context.Crypto.GenerateKeypair()
	if err != nil {
		return nil, err
	}
	return key.PrivateKey(), nil
}
func (k *keyManager) Store(privateKey virgilcrypto.PrivateKey, alias string, password string) error {
	key, err := k.Context.Crypto.ExportPrivateKey(privateKey, password)
	if err != nil {
		return err
	}
	item := &virgil.StorageItem{
		Data: key,
		Name: alias,
	}
	return k.Context.Storage.Store(item)
}
func (k *keyManager) Load(alias string, password string) (virgilcrypto.PrivateKey, error) {
	item, err := k.Context.Storage.Load(alias)
	if err != nil {
		return nil, err
	}

	key, err := k.Context.Crypto.ImportPrivateKey(item.Data, password)
	if err != nil {
		return nil, err
	}

	return key, nil
}
