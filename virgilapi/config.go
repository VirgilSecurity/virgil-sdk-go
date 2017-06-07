package virgilapi

import (
	virgil "gopkg.in/virgil.v4"
	"gopkg.in/virgil.v4/virgilcrypto"
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
