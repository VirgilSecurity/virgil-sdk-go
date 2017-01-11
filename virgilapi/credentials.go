package virgilapi

import "gopkg.in/virgil.v4/virgilcrypto"

type AppCredentials struct {
	AppId string
	Key   virgilcrypto.PrivateKey
}
