package virgilapi

import (
	"gopkg.in/virgil.v4"
	"gopkg.in/virgil.v4/transport"
)

type Api struct {
	context *Context
	Cards   CardManager
	Keys    KeyManager
}

func New(accessToken string) (*Api, error) {

	cli, err := virgil.NewClient(accessToken)
	if err != nil {
		return nil, err
	}
	context := &Context{
		client:        cli,
		storage:       &virgil.FileStorage{RootDir: "."},
		requestSigner: &virgil.RequestSigner{},
	}

	return &Api{
		context: context,
		Cards:   &cardManager{context: context},
		Keys:    &keyManager{context: context},
	}, nil
}

func NewWithConfig(config Config) (*Api, error) {

	params := make([]func(client *virgil.Client), 0)
	if err := virgil.Crypto().SetKeyType(config.KeyType); err != nil {
		return nil, err
	}

	if config.ClientParams != nil {
		clientParams := config.ClientParams //TODO

		urls := map[transport.ServiceType]string{
			virgil.Cardservice:     clientParams.CardServiceURL,
			virgil.ROCardService:   clientParams.ReadOnlyCardServiceURL,
			virgil.IdentityService: clientParams.IdentityServiceURL,
			virgil.VRAService:      clientParams.VRAServiceURL,
		}

		params = append(params, virgil.ClientTransport(transport.NewTransportClient(virgil.DefaultHTTPEndpoints, urls)))
	}

	var validator virgil.CardsValidator

	if len(config.CardVerifiers) > 0 {
		val := virgil.NewCardsValidator()
		if !config.SkipBuiltInVerifiers {
			val.AddDefaultVerifiers()
		}
		for id, v := range config.CardVerifiers {
			key, err := virgil.Crypto().ImportPublicKey(v)
			if err != nil {
				return nil, err
			}
			val.AddVerifier(id, key)
		}
		validator = val
		params = append(params, virgil.ClientCardsValidator(validator))
	} else {
		if config.SkipBuiltInVerifiers {
			validator = virgil.NewCardsValidator()
			params = append(params, virgil.ClientCardsValidator(validator))
		}
	}

	cli, err := virgil.NewClient(config.Token, params...)

	if err != nil {
		return nil, err
	}

	var root string
	if config.KeyStoragePath != "" {
		root = config.KeyStoragePath
	} else {
		root = "."
	}
	var key *appKey
	if config.Credentials != nil {
		k, err := virgil.Crypto().ImportPrivateKey(config.Credentials.PrivateKey, config.Credentials.PrivateKeyPassword)
		if err != nil {
			return nil, err
		}
		key = &appKey{id: config.Credentials.AppId, key: k}
	}

	context := &Context{
		client:        cli,
		storage:       &virgil.FileStorage{RootDir: root},
		requestSigner: &virgil.RequestSigner{},
		appKey:        key,
		validator:     validator,
	}

	return &Api{
		context: context,
		Cards:   &cardManager{context: context},
		Keys:    &keyManager{context: context},
	}, nil
}

func (a *Api) Encrypt(data Buffer, recipients ...*Card) (Buffer, error) {
	return Cards(recipients).Encrypt(data)
}

//EncryptString is the same as Encrypt but expects any string
func (a *Api) EncryptString(data string, recipients ...*Card) (Buffer, error) {
	return Cards(recipients).EncryptString(data)
}

func (a *Api) Decrypt(data Buffer, key *Key) (Buffer, error) {
	return key.Decrypt(data)
}

// Decrypt expects string, received by calling ToBase64String on Buffer, received from Encrypt or EncryptString
func (a *Api) DecryptString(data string, key *Key) (Buffer, error) {
	return key.DecryptString(data)
}

func (a *Api) Sign(data Buffer, key *Key) (Buffer, error) {
	return key.Sign(data)
}

func (a *Api) SignString(data string, key *Key) (Buffer, error) {
	return key.SignString(data)
}

func (a *Api) Verify(data Buffer, signature Buffer, signerCard *Card) (bool, error) {
	return signerCard.Verify(data, signature)
}

// VerifyString is the same as Verify but works with ordinary strings
func (a *Api) VerifyString(data string, signature string, signerCard *Card) (bool, error) {
	return signerCard.VerifyString(data, signature)
}

func (a *Api) SignThenEncrypt(data Buffer, signerKey *Key, recipients ...*Card) (Buffer, error) {
	return signerKey.SignThenEncrypt(data, recipients...)
}

func (a *Api) SignThenEncryptString(data string, signerKey *Key, recipients ...*Card) (Buffer, error) {
	return signerKey.SignThenEncryptString(data, recipients...)
}

func (a *Api) DecryptThenVerify(data Buffer, key *Key, signerCard *Card) (Buffer, error) {
	return key.DecryptThenVerify(data, signerCard)
}

// DecryptThenVerifyString expects data to be in base64 encoding
func (a *Api) DecryptThenVerifyString(data string, key *Key, signerCard *Card) (Buffer, error) {
	return key.DecryptThenVerifyString(data, signerCard)
}
