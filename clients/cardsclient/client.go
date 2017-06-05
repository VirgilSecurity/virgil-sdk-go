package cardsclient

import (
	"gopkg.in/virgil.v4"
	"gopkg.in/virgil.v4/clients"
	"gopkg.in/virgil.v4/errors"
)

type Client struct {
	*clients.BaseClient
}

// NewClient create a new instance of Virgil Cards client
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

// AddRelation adds signature of the card signer trusts
func (c *Client) AddRelation(request *virgil.SignableRequest) (*virgil.Card, error) {
	if request == nil || len(request.Snapshot) == 0 || len(request.Meta.Signatures) != 1 {
		return nil, errors.New("request must not be empty and must contain exactly 1 relation signature")
	}

	var id string
	for k := range request.Meta.Signatures {
		id = k
	}

	var res *virgil.CardResponse
	err := c.TransportClient.Call(AddRelation, request, &res, id)

	if err != nil {
		return nil, err
	}
	return c.ConvertToCardAndValidate(res)
}

// AddRelation adds signature of the card signer trusts
func (c *Client) DeleteRelation(request *virgil.SignableRequest) (*virgil.Card, error) {
	if request == nil || len(request.Snapshot) == 0 || len(request.Meta.Signatures) != 1 {
		return nil, errors.New("request must not be empty and must contain exactly 1 signature")
	}

	var id string
	for k := range request.Meta.Signatures {
		id = k
	}

	var res *virgil.CardResponse
	err := c.TransportClient.Call(DeleteRelation, request, &res, id)

	if err != nil {
		return nil, err
	}
	return c.ConvertToCardAndValidate(res)
}
