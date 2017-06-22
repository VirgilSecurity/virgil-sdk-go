package securechat

import (
	"errors"

	"gopkg.in/virgil.v5"
	"gopkg.in/virgil.v5/clients"
	"gopkg.in/virgil.v5/virgilcrypto"
)

type Client struct {
	*clients.BaseClient
	ephemeralCardsValidator virgil.CardsValidator
}

// NewClient create a new instance of Virgil Identity service client
func NewClient(accessToken string, opts ...func(*clients.BaseClient)) (*Client, error) {

	baseClient, err := clients.NewClient(accessToken, URL, Endpoints, opts...)

	if err != nil {
		return nil, err
	}

	c := &Client{
		BaseClient:              baseClient,
		ephemeralCardsValidator: virgil.NewCardsValidator(),
	}

	return c, nil
}

// CreateLTCCard posts user LTC card to PFS server. Card must be self-signed and user-identity signed
func (c *Client) CreateRecipient(icCardID string, ltc *virgil.SignableRequest, otcs []*virgil.SignableRequest) error {
	if ltc == nil || len(ltc.Snapshot) == 0 || len(ltc.Meta.Signatures) != 1 || len(otcs) == 0 {
		return errors.New("ltc is empty or number of signatures is not 1 or otcs list is empty")
	}

	for _, otc := range otcs {
		if otc == nil || len(otc.Snapshot) == 0 || len(otc.Meta.Signatures) != 1 {
			return errors.New("otc is empty or number of signatures is not 1")
		}
	}

	request := &CreateRecipientRequest{
		LTC:  ltc,
		OTCS: otcs,
	}

	var res *CreateRecipientResponse
	err := c.TransportClient.Call(CreateRecipient, request, &res, icCardID)

	if err != nil {
		return err
	}

	if len(otcs) != len(res.OTCS) {
		return errors.New("The number of added and returned OTCs does not match.")
	}

	return nil
}

// CreateLTCCard posts user LTC card to PFS server. Card must be self-signed and user-identity signed
func (c *Client) CreateLTCCard(icCardID string, request *virgil.SignableRequest) error {
	if request == nil || len(request.Snapshot) == 0 || len(request.Meta.Signatures) != 1 {
		return errors.New("request is empty or number of signatures is not 1")
	}
	var res *virgil.CardResponse
	err := c.TransportClient.Call(CreateLTCCard, request, &res, icCardID)

	if err != nil {
		return err
	}
	return nil
}

// CreateLTCCard posts user LTC card to PFS server. Card must be self-signed and user-identity signed
func (c *Client) UploadOTCCards(icCardID string, requests []*virgil.SignableRequest) error {
	if len(requests) == 0 {
		return errors.New("nothing to upload")
	}

	for _, r := range requests {
		if r == nil || len(r.Snapshot) == 0 || len(r.Meta.Signatures) != 2 {
			return errors.New("request is empty or number of signatures is not 2")
		}
	}
	var res []*virgil.CardResponse
	err := c.TransportClient.Call(UploadOTCCards, requests, &res, icCardID)

	if err != nil {
		return err
	}

	return nil
}

// GetUserCredentials receives a set of credentials for specified identities
func (c *Client) GetUserCredentials(identities ...string) ([]*Credentials, error) {
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

		if r.IdentityCard == nil || r.LTC == nil {
			return nil, errors.New("Either Identity card or LTC card is empty")
		}
		ic, err := c.ConvertToCardAndValidate(r.IdentityCard)
		if err != nil {
			return nil, err
		}

		identityKey := map[string]virgilcrypto.PublicKey{
			ic.ID: ic.PublicKey,
		}

		ltc, err := c.ConvertToCardAndValidateExtra(r.LTC, identityKey, false)
		if err != nil {
			return nil, err
		}

		cred := &Credentials{
			IdentityCard: ic,
			LTC:          ltc,
		}

		if r.OTC != nil {
			otc, err := c.ConvertToCardAndValidateExtra(r.OTC, identityKey, false)

			if err != nil {
				return nil, err
			}
			cred.OTC = otc
		}
		creds[i] = cred
	}
	return creds, nil
}

func (c *Client) ConvertToCardAndValidateExtra(response *virgil.CardResponse, extraKeys map[string]virgilcrypto.PublicKey, validateSelfSign bool) (*virgil.Card, error) {

	card, err := response.ToCard()

	if err != nil {
		return nil, err
	}

	if c.ephemeralCardsValidator != nil {
		err := c.ephemeralCardsValidator.ValidateExtra(card, extraKeys, validateSelfSign)
		if err != nil {
			return nil, err
		}
	}
	return card, nil
}
