package pfs

import (
	"gopkg.in/virgil.v4"
	"gopkg.in/virgil.v4/clients/cardsroclient"
)

type Config struct {
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
