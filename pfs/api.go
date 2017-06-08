package pfs

import (
	"fmt"

	"gopkg.in/virgil.v4"
	"gopkg.in/virgil.v4/errors"
	"gopkg.in/virgil.v4/virgilcrypto"
)

type Api struct {
	Client         *Client
	Crypto         virgilcrypto.PFS
	SessionManager *SessionManager
	Storage        virgil.KeyStorage
}

func New(config *Config) (*Api, error) {

	cli, err := NewClient(config.AccessToken)

	if err != nil {
		return nil, err
	}

	pfsCrypto, ok := virgil.Crypto().(virgilcrypto.PFS)

	if !ok {
		return nil, errors.New("Crypto does not implement PFS")
	}
	api := &Api{
		Client:         cli,
		Crypto:         pfsCrypto,
		SessionManager: &SessionManager{},
	}

	return api, nil

}

func (a *Api) InitTalkWith(identity string) error {

	creds, err := a.Client.GetUserCredentials(identity)
	if err != nil {
		return err
	}
	for _, c := range creds {
		fmt.Println(c.IdentityCard)
	}
	return nil
}
