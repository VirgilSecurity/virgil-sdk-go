package virgilapi

import (
	"gopkg.in/virgil.v4"
	"gopkg.in/virgil.v4/virgilcrypto"
)

type appKey struct {
	id  string
	key virgilcrypto.PrivateKey
}

type Context struct {
	client        *virgil.Client
	storage       virgil.KeyStorage
	requestSigner *virgil.RequestSigner
	appKey        *appKey
}
