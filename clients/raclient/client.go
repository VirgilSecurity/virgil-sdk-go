package raclient

import (
	"encoding/json"

	"gopkg.in/virgil.v5"
	"gopkg.in/virgil.v5/clients"
	"gopkg.in/virgil.v5/errors"
)

type Client struct {
	*clients.BaseClient
}

// NewClient create a new instance of Virgil Registration Authority client
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

// CreateCard posts card create request to server where it checks signatures and adds it
func (c *Client) CreateCard(request *virgil.SignableRequest) (*virgil.Card, error) {
	if request == nil || len(request.Snapshot) == 0 || len(request.Meta.Signatures) == 0 {
		return nil, errors.New("request is empty or does not contain any signatures")
	}
	var res *virgil.CardResponse
	err := c.TransportClient.Call(CreateCard, request, &res)

	if err != nil {
		return nil, err
	}
	return c.ConvertToCardAndValidate(res)
}

// RevokeCard deletes card from server
func (c *Client) RevokeCard(request *virgil.SignableRequest) error {
	if request == nil {
		return errors.New("request is nil")
	}
	req := &virgil.RevokeCardRequest{}
	err := json.Unmarshal(request.Snapshot, req)
	if err != nil {
		return errors.Wrap(err, "")
	}

	return c.TransportClient.Call(RevokeCard, request, nil, req.ID)
}
