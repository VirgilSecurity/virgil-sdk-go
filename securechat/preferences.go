package securechat

import (
	"gopkg.in/virgil.v5"
	"gopkg.in/virgil.v5/clients/cardsroclient"
)

type Preferences struct {
	AccessToken        string
	IdentityCardID     string
	PrivateKey         virgil.Buffer
	PrivateKeyPassword string
	//the amount of One Time Cards to create. Default 100
	OTCCount       int
	PFSClient      *Client
	CardsClient    *cardsroclient.Client
	KeyStoragePath string
}
