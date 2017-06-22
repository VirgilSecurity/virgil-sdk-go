package virgilapi

import (
	"gopkg.in/virgil.v5"
	"gopkg.in/virgil.v5/virgilcrypto"
)

type Config struct {
	Token                string
	Credentials          *AppCredentials
	ClientParams         *ClientParams
	KeyStoragePath       string
	CardVerifiers        map[string]virgil.Buffer
	KeyType              virgilcrypto.KeyType
	SkipBuiltInVerifiers bool
}
