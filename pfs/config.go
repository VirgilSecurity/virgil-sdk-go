package pfs

import "gopkg.in/virgil.v4"

type Config struct {
	AccessToken        string
	IdentityCardID     string
	PrivateKey         virgil.Buffer
	PrivateKeyPassword string
}
