package virgilapi

import (
	"gopkg.in/virgil.v4"
	"gopkg.in/virgil.v4/clients/cardsclient"
	"gopkg.in/virgil.v4/clients/cardsroclient"
	"gopkg.in/virgil.v4/clients/identityclient"
	"gopkg.in/virgil.v4/clients/raclient"
	"gopkg.in/virgil.v4/virgilcrypto"
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
	requestSigner  *virgil.RequestSigner
	appKey         *appKey
	validator      virgil.CardsValidator
}
