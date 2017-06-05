package pfs

import (
	"errors"

	"gopkg.in/virgil.v4"
	"gopkg.in/virgil.v4/transport"
)

var DefaultServiceBaseURLs map[transport.ServiceType]string = initBaseURLs()

type EphemeralCardsClient struct {
	*virgil.Client
}

// NewClient create a new instance of Virgil client
func NewClient(accessToken string, opts ...func(*virgil.Client)) (*EphemeralCardsClient, error) {
	v, err := virgil.MakeDefaultCardsValidator()
	if err != nil {
		return nil, err
	}

	c := &EphemeralCardsClient{
		Client: &virgil.Client{
			TransportClient: transport.NewTransportClient(DefaultHTTPEndpoints, DefaultServiceBaseURLs),
			CardsValidator:  v,
		},
	}

	for _, option := range opts {
		option(c.Client)
	}

	c.TransportClient.SetToken(accessToken)
	return c, nil
}

// CreateLTCCard posts user LTC card to PFS server. Card must be self-signed and user-identity signed
func (c *EphemeralCardsClient) CreateLTCCard(icCardID string, request *virgil.SignableRequest) (*virgil.Card, error) {
	if request == nil || len(request.Snapshot) == 0 || len(request.Meta.Signatures) != 2 {
		return nil, errors.New("request is empty or number of signatures is not 2")
	}
	var res *virgil.CardResponse
	err := c.TransportClient.Call(CreateLTCCard, request, &res, icCardID)

	if err != nil {
		return nil, err
	}
	return c.ConvertToCardAndValidate(res)
}

// CreateLTCCard posts user LTC card to PFS server. Card must be self-signed and user-identity signed
func (c *EphemeralCardsClient) UploadOTCCards(icCardID string, requests []*virgil.SignableRequest) ([]*virgil.Card, error) {
	if len(requests) == 0 {
		return nil, errors.New("nothing to upload")
	}

	for _, r := range requests {
		if r == nil || len(r.Snapshot) == 0 || len(r.Meta.Signatures) != 2 {
			return nil, errors.New("request is empty or number of signatures is not 2")
		}
	}
	var res []*virgil.CardResponse
	err := c.TransportClient.Call(UploadOTCCards, requests, &res, icCardID)

	if err != nil {
		return nil, err
	}

	resCards := make([]*virgil.Card, len(res))
	for i, r := range res {
		resCards[i], err = c.ConvertToCardAndValidate(r)
		if err != nil {
			return nil, err
		}
	}
	return resCards, nil
}

// GetUserCredentials receives a set of credentials for specified identities
func (c *EphemeralCardsClient) GetUserCredentials(identities ...string) ([]*Credentials, error) {
	if len(identities) == 0 {
		return nil, errors.New("nothing to search for")
	}
	for _, i := range identities {
		if i == "" {
			return nil, errors.New("identity is empty")
		}
	}
	var res []*CredentialsResponse
	err := c.TransportClient.Call(GetUserCredentials, &CredentialsRequest{Identities: identities}, &res)

	if err != nil {
		return nil, err
	}

	creds := make([]*Credentials, len(res))
	for i, r := range res {
		ic, err := c.ConvertToCardAndValidate(r.IdentityCard)
		if err != nil {
			return nil, err
		}
		ltc, err := c.ConvertToCardAndValidate(r.LTC)
		if err != nil {
			return nil, err
		}

		cred := &Credentials{
			IdentityCard: ic,
			LTC:          ltc,
		}

		if r.OTC != nil {
			otc, err := c.ConvertToCardAndValidate(r.OTC)
			if err != nil {
				return nil, err
			}
			cred.OTC = otc
		}
		creds[i] = cred
	}
	return creds, nil
}

func initBaseURLs() map[transport.ServiceType]string {
	res := map[transport.ServiceType]string{}
	for k, v := range virgil.DefaultServiceBaseURLs {
		res[k] = v
	}

	res[PFSService] = "https://pfs-stg.virgilsecurity.com"
	return res
}
