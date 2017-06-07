package virgilapi

import virgil "gopkg.in/virgil.v4"

type AppCredentials struct {
	AppId              string
	PrivateKey         virgil.Buffer
	PrivateKeyPassword string
}
