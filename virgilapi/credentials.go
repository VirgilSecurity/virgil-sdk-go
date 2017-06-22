package virgilapi

import "gopkg.in/virgil.v5"

type AppCredentials struct {
	AppId              string
	PrivateKey         virgil.Buffer
	PrivateKeyPassword string
}
