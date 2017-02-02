package virgilapi

import (
	"gopkg.in/virgil.v4"
)

type KeyManager interface {
	Generate() (*Key, error)
	Store(keypair *Key, alias string, password string) error
	Load(alias string, password string) (*Key, error)
}

type keyManager struct {
	Context *Context
}

func (k *keyManager) Generate() (*Key, error) {
	key, err := virgil.Crypto().GenerateKeypair()
	if err != nil {
		return nil, err
	}
	return &Key{
		Context:    k.Context,
		PrivateKey: key.PrivateKey(),
	}, nil
}
func (k *keyManager) Store(privateKey *Key, alias string, password string) error {
	key, err := virgil.Crypto().ExportPrivateKey(privateKey.PrivateKey, password)
	if err != nil {
		return err
	}
	item := &virgil.StorageItem{
		Data: key,
		Name: alias,
	}
	return k.Context.storage.Store(item)
}
func (k *keyManager) Load(alias string, password string) (*Key, error) {
	item, err := k.Context.storage.Load(alias)
	if err != nil {
		return nil, err
	}

	key, err := virgil.Crypto().ImportPrivateKey(item.Data, password)
	if err != nil {
		return nil, err
	}

	return &Key{
		Context:    k.Context,
		PrivateKey: key,
	}, nil
}
