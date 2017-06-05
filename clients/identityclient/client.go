package identityclient

import (
	"gopkg.in/virgil.v4"
	"gopkg.in/virgil.v4/clients"
	"gopkg.in/virgil.v4/errors"
)

type Client struct {
	*clients.BaseClient
}

// NewClient create a new instance of Virgil Identity service client
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

func (c *Client) VerifyIdentity(request *virgil.VerifyRequest) (*virgil.VerifyResponse, error) {
	if request == nil {
		return nil, errors.New("request is nil")
	}
	var res *virgil.VerifyResponse
	err := c.TransportClient.Call(VerifyIdentity, request, &res)

	if err != nil {
		return nil, err
	}

	return res, nil
}

func (c *Client) ConfirmIdentity(request *virgil.ConfirmRequest) (*virgil.ConfirmResponse, error) {
	if request == nil {
		return nil, errors.New("request is nil")
	}
	var res *virgil.ConfirmResponse

	err := c.TransportClient.Call(ConfirmIdentity, request, &res)

	if err != nil {
		return nil, err
	}

	return res, nil
}

func (c *Client) ValidateIdentity(request *virgil.ValidateRequest) error {
	if request == nil {
		return errors.New("request is nil")
	}
	return c.TransportClient.Call(ValidateIdentity, request, nil)
}
