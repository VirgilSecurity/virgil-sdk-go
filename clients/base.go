package clients

import (
	"gopkg.in/virgil.v4"
	"gopkg.in/virgil.v4/transport"
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

func (b *BaseClient) ConvertToCardAndValidate(response *virgil.CardResponse) (*virgil.Card, error) {

	card, err := response.ToCard()

	if err != nil {
		return nil, err
	}

	if b.CardsValidator != nil {
		ok, err := b.CardsValidator.Validate(card)
		if !ok {
			return nil, err
		}
	}
	return card, nil
}
