package virgilapi

import (
	"gopkg.in/virgil.v4"
)

type Context struct {
	client        *virgil.Client
	storage       virgil.KeyStorage
	requestSigner *virgil.RequestSigner

	Config Config
}
