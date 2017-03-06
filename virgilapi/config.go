package virgilapi

import "gopkg.in/virgil.v4/virgilcrypto"

type Config struct {
	Token                string
	Credentials          *AppCredentials
	ClientParams         *ClientParams
	KeyStoragePath       string
	CardVerifiers        map[string]Buffer
	KeyType              virgilcrypto.KeyType
	SkipBuiltInVerifiers bool
}
