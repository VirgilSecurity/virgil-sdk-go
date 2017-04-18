package virgilapi

import (
	"gopkg.in/virgil.v4"
)

type KeyManager interface {
	Generate() (*Key, error)
	Load(alias string, password string) (*Key, error)
	Import(key Buffer, password string) (*Key, error)
}

type keyManager struct {
	context *Context
}

func (k *keyManager) Generate() (*Key, error) {
	key, err := virgil.Crypto().GenerateKeypair()
	if err != nil {
		return nil, err
	}
	return &Key{
		context:    k.context,
		privateKey: key.PrivateKey(),
	}, nil
}

func (k *keyManager) Load(alias string, password string) (*Key, error) {
	item, err := k.context.storage.Load(alias)
	if err != nil {
		return nil, err
	}

	key, err := virgil.Crypto().ImportPrivateKey(item.Data, password)
	if err != nil {
		return nil, err
	}

	return &Key{
		context:    k.context,
		privateKey: key,
	}, nil
}

//Import imports base64 encoded private key
func (k *keyManager) Import(key Buffer, password string) (*Key, error) {
	pkey, err := virgil.Crypto().ImportPrivateKey(key, password)

	if err != nil {
		return nil, err
	}

	return &Key{
		context:    k.context,
		privateKey: pkey,
	}, nil
}
