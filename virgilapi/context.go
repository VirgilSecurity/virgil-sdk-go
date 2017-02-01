package virgilapi

import (
	"gopkg.in/virgil.v4"
	"gopkg.in/virgil.v4/virgilcrypto"
)

type Context struct {
	Client        *virgil.Client
	Crypto        virgilcrypto.Crypto
	Storage       virgil.KeyStorage
	Credentials   AppCredentials
	RequestSigner *virgil.RequestSigner
	CardVerifiers map[string]Buffer
}
