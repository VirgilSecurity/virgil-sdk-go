package clients

import (
	"gopkg.in/virgil.v5"
	"gopkg.in/virgil.v5/transport"
	"gopkg.in/virgil.v5/virgilcrypto"
)

type BaseClient struct {
	TransportClient transport.Client
	CardsValidator  virgil.CardsValidator
}

// ClientTransport sets card service protocol for a Virgil client
//
func ClientTransport(transportClient transport.Client) func(*BaseClient) {
	return func(client *BaseClient) {
		client.TransportClient = transportClient
	}
}

// ClientCardsValidator sets custom card validaor for a Virgil client
//
func ClientCardsValidator(validator virgil.CardsValidator) func(*BaseClient) {
	return func(client *BaseClient) {
		client.CardsValidator = validator
	}
}

// ServiceUrl replaces clients' base URL with the provided one if it is not empty
func ServiceUrl(url string) func(client *BaseClient) {
	return func(client *BaseClient) {
		if url != "" {
			client.TransportClient.SetURL(url)
		}

	}
}

func NewClient(accessToken string, url string, endpoints map[transport.Endpoint]*transport.HTTPEndpoint, opts ...func(*BaseClient)) (*BaseClient, error) {
	v, err := virgil.MakeDefaultCardsValidator()
	if err != nil {
		return nil, err
	}

	c := &BaseClient{
		TransportClient: transport.NewTransportClient(url, endpoints),
		CardsValidator:  v,
	}

	for _, option := range opts {
		option(c)
	}

	c.TransportClient.SetToken(accessToken)
	return c, nil
}

func (b *BaseClient) ConvertToCardAndValidateExtra(response *virgil.CardResponse, extraKeys map[string]virgilcrypto.PublicKey, validateSelfSign bool) (*virgil.Card, error) {

	card, err := response.ToCard()

	if err != nil {
		return nil, err
	}

	if b.CardsValidator != nil {
		err := b.CardsValidator.ValidateExtra(card, extraKeys, validateSelfSign)
		if err != nil {
			return nil, err
		}
	}
	return card, nil
}

func (b *BaseClient) ConvertToCardAndValidate(response *virgil.CardResponse) (*virgil.Card, error) {

	return b.ConvertToCardAndValidateExtra(response, nil, true)
}
