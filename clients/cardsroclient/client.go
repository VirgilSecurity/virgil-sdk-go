package cardsroclient

import (
	"gopkg.in/virgil.v5"
	"gopkg.in/virgil.v5/clients"
	"gopkg.in/virgil.v5/errors"
)

type Client struct {
	*clients.BaseClient
}

// NewClient create a new instance of Virgil Cards Readonly client
func New(accessToken string, opts ...func(*clients.BaseClient)) (*Client, error) {

	baseClient, err := clients.NewClient(accessToken, URL, Endpoints, opts...)

	if err != nil {
		return nil, err
	}

	c := &Client{
		BaseClient: baseClient,
	}
	return c, nil
}

// GetCard return a card from Virgil Read Only Card service
func (c *Client) GetCard(id string) (*virgil.Card, error) {
	var res *virgil.CardResponse
	err := c.TransportClient.Call(GetCard, nil, &res, id)
	if err != nil {
		return nil, err
	}
	return c.ConvertToCardAndValidate(res)
}

func (c *Client) SearchCards(criteria *virgil.Criteria) ([]*virgil.Card, error) {
	if criteria == nil || len(criteria.Identities) == 0 {
		return nil, errors.New("search criteria cannot be empty")
	}
	var res []*virgil.CardResponse
	err := c.TransportClient.Call(SearchCards, criteria, &res)
	if err != nil {
		return nil, err
	}

	var cards []*virgil.Card
	for _, v := range res {
		card, err := c.ConvertToCardAndValidate(v)
		if err != nil {
			return nil, err
		}
		cards = append(cards, card)
	}
	return cards, nil
}
