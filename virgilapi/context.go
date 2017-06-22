package virgilapi

import (
	"gopkg.in/virgil.v5"
	"gopkg.in/virgil.v5/clients/cardsclient"
	"gopkg.in/virgil.v5/clients/cardsroclient"
	"gopkg.in/virgil.v5/clients/identityclient"
	"gopkg.in/virgil.v5/clients/raclient"
	"gopkg.in/virgil.v5/virgilcrypto"
)

type appKey struct {
	id  string
	key virgilcrypto.PrivateKey
}

type Context struct {
	cardsClient    *cardsclient.Client
	cardsROClient  *cardsroclient.Client
	raClient       *raclient.Client
	identityClient *identityclient.Client
	storage        virgil.KeyStorage
	appKey         *appKey
	validator      virgil.CardsValidator
}
