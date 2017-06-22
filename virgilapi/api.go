package virgilapi

import (
	"gopkg.in/virgil.v5"
	"gopkg.in/virgil.v5/clients"
	"gopkg.in/virgil.v5/clients/cardsclient"
	"gopkg.in/virgil.v5/clients/cardsroclient"
	"gopkg.in/virgil.v5/clients/identityclient"
	"gopkg.in/virgil.v5/clients/raclient"
)

type Api struct {
	context *Context
	Cards   CardManager
	Keys    KeyManager
}

func New(accessToken string) (*Api, error) {

	cardsClient, err := cardsclient.New(accessToken)
	if err != nil {
		return nil, err
	}

	cardsROClient, err := cardsroclient.New(accessToken)
	if err != nil {
		return nil, err
	}

	raClient, err := raclient.New(accessToken)
	if err != nil {
		return nil, err
	}

	identityClient, err := identityclient.New(accessToken)
	if err != nil {
		return nil, err
	}

	context := &Context{
		cardsClient:    cardsClient,
		cardsROClient:  cardsROClient,
		raClient:       raClient,
		identityClient: identityClient,
		storage:        &virgil.FileStorage{RootDir: "."},
	}

	return &Api{
		context: context,
		Cards:   &cardManager{context: context},
		Keys:    &keyManager{context: context},
	}, nil
}

func NewWithConfig(config Config) (*Api, error) {

	cardsParams := make([]func(client *clients.BaseClient), 0)
	cardsROParams := make([]func(client *clients.BaseClient), 0)
	identityParams := make([]func(client *clients.BaseClient), 0)
	raParams := make([]func(client *clients.BaseClient), 0)

	if err := virgil.Crypto().SetKeyType(config.KeyType); err != nil {
		return nil, err
	}

	if config.ClientParams != nil {
		clientParams := config.ClientParams

		cardsParams = append(cardsParams, clients.ServiceUrl(clientParams.CardServiceURL))
		cardsROParams = append(cardsROParams, clients.ServiceUrl(clientParams.ReadOnlyCardServiceURL))
		identityParams = append(identityParams, clients.ServiceUrl(clientParams.IdentityServiceURL))
		raParams = append(raParams, clients.ServiceUrl(clientParams.RAServiceURL))
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

		cardsParams = append(cardsParams, clients.ClientCardsValidator(validator))
		cardsROParams = append(cardsROParams, clients.ClientCardsValidator(validator))
		identityParams = append(identityParams, clients.ClientCardsValidator(validator))
		raParams = append(raParams, clients.ClientCardsValidator(validator))

	} else {
		if config.SkipBuiltInVerifiers {
			validator = virgil.NewCardsValidator()
			cardsParams = append(cardsParams, clients.ClientCardsValidator(validator))
			cardsROParams = append(cardsROParams, clients.ClientCardsValidator(validator))
			identityParams = append(identityParams, clients.ClientCardsValidator(validator))
			raParams = append(raParams, clients.ClientCardsValidator(validator))
		}
	}

	cardsClient, err := cardsclient.New(config.Token)
	if err != nil {
		return nil, err
	}

	cardsROClient, err := cardsroclient.New(config.Token)
	if err != nil {
		return nil, err
	}

	raClient, err := raclient.New(config.Token)
	if err != nil {
		return nil, err
	}

	identityClient, err := identityclient.New(config.Token)
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
		cardsClient:    cardsClient,
		cardsROClient:  cardsROClient,
		raClient:       raClient,
		identityClient: identityClient,
		storage:        &virgil.FileStorage{RootDir: root},
		appKey:         key,
		validator:      validator,
	}

	return &Api{
		context: context,
		Cards:   &cardManager{context: context},
		Keys:    &keyManager{context: context},
	}, nil
}

func (a *Api) Encrypt(data virgil.Buffer, recipients ...*Card) (virgil.Buffer, error) {
	return Cards(recipients).Encrypt(data)
}

//EncryptString is the same as Encrypt but expects any string
func (a *Api) EncryptString(data string, recipients ...*Card) (virgil.Buffer, error) {
	return Cards(recipients).EncryptString(data)
}

func (a *Api) Decrypt(data virgil.Buffer, key *Key) (virgil.Buffer, error) {
	return key.Decrypt(data)
}

// Decrypt expects string, received by calling ToBase64String on Buffer, received from Encrypt or EncryptString
func (a *Api) DecryptString(data string, key *Key) (virgil.Buffer, error) {
	return key.DecryptString(data)
}

func (a *Api) Sign(data virgil.Buffer, key *Key) (virgil.Buffer, error) {
	return key.Sign(data)
}

func (a *Api) SignString(data string, key *Key) (virgil.Buffer, error) {
	return key.SignString(data)
}

func (a *Api) Verify(data virgil.Buffer, signature virgil.Buffer, signerCard *Card) error {
	return signerCard.Verify(data, signature)
}

// VerifyString is the same as Verify but works with ordinary strings
func (a *Api) VerifyString(data string, signature string, signerCard *Card) error {
	return signerCard.VerifyString(data, signature)
}

func (a *Api) SignThenEncrypt(data virgil.Buffer, signerKey *Key, recipients ...*Card) (virgil.Buffer, error) {
	return signerKey.SignThenEncrypt(data, recipients...)
}

func (a *Api) SignThenEncryptString(data string, signerKey *Key, recipients ...*Card) (virgil.Buffer, error) {
	return signerKey.SignThenEncryptString(data, recipients...)
}

func (a *Api) DecryptThenVerify(data virgil.Buffer, key *Key, signerCard *Card) (virgil.Buffer, error) {
	return key.DecryptThenVerify(data, signerCard)
}

// DecryptThenVerifyString expects data to be in base64 encoding
func (a *Api) DecryptThenVerifyString(data string, key *Key, signerCard *Card) (virgil.Buffer, error) {
	return key.DecryptThenVerifyString(data, signerCard)
}
