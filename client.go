/*
Copyright (C) 2015-2016 Virgil Security Inc.

Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>

All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

  (1) Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  (2) Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in
  the documentation and/or other materials provided with the
  distribution.

  (3) Neither the name of the copyright holder nor the names of its
  contributors may be used to endorse or promote products derived
  from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/

package virgil

import (
	"encoding/json"

	"gopkg.in/virgil.v4/errors"
	"gopkg.in/virgil.v4/transport"
	"gopkg.in/virgil.v4/transport/endpoints"
	"gopkg.in/virgil.v4/transport/virgilhttp"
)

var (
	ErrNotFound = transport.ErrNotFound
)

// ClientTransport set card service protocol for a Virgil client
//
func ClientTransport(transportClient transport.Client) func(*Client) {
	return func(client *Client) {
		client.transportClient = transportClient
	}
}

// ClientCardsValidator set custom card validaor for a Virgil client
//
func ClientCardsValidator(validator CardsValidator) func(*Client) {
	return func(client *Client) {
		client.cardsValidator = validator
	}
}

// NewClient create a new instance of Virgil client
func NewClient(accessToken string, opts ...func(*Client)) (*Client, error) {
	v, err := makeDefaultCardsValidator()
	if err != nil {
		return nil, err
	}

	c := &Client{
		transportClient: virgilhttp.NewTransportClient(
			"https://cards.virgilsecurity.com",
			"https://cards-ro.virgilsecurity.com",
			"https://identity.virgilsecurity.com",
			"https://ra.virgilsecurity.com"),
		cardsValidator: v,
	}

	for _, option := range opts {
		option(c)
	}

	c.transportClient.SetToken(accessToken)
	return c, nil
}

// A Client manages communication with Virgil Security API.
type Client struct {
	transportClient transport.Client
	cardsValidator  CardsValidator
}

// GetCard return a card from Virgil Read Only Card service
func (c *Client) GetCard(id string) (*Card, error) {
	var res *CardResponse
	err := c.transportClient.Call(endpoints.GetCard, nil, &res, id)
	if err != nil {
		return nil, err
	}
	return c.convertToCardAndValidate(res)
}

// CreateCard posts card create request to server where it checks signatures and adds it
func (c *Client) CreateCard(request *SignableRequest) (*Card, error) {
	var res *CardResponse
	err := c.transportClient.Call(endpoints.CreateCard, request, &res)

	if err != nil {
		return nil, err
	}
	return c.convertToCardAndValidate(res)
}

// RevokeCard deletes card from server
func (c *Client) RevokeCard(request *SignableRequest) error {

	req := &RevokeCardRequest{}
	err := json.Unmarshal(request.Snapshot, req)
	if err != nil {
		return errors.Wrap(err, "")
	}

	return c.transportClient.Call(endpoints.RevokeCard, request, nil, req.ID)
}

func (c *Client) SearchCards(criteria Criteria) ([]*Card, error) {
	if len(criteria.Identities) == 0 {
		return nil, errors.New("identites cannot be empty")
	}
	var res []*CardResponse
	err := c.transportClient.Call(endpoints.SearchCards, &Criteria{
		Identities:   criteria.Identities,
		IdentityType: criteria.IdentityType,
		Scope:        criteria.Scope,
	}, &res)
	if err != nil {
		return nil, err
	}

	var cards []*Card
	for _, v := range res {
		card, err := c.convertToCardAndValidate(v)
		if err != nil {
			return nil, err
		}
		cards = append(cards, card)
	}
	return cards, nil
}

func (c *Client) VerifyIdentity(request *VerifyRequest) (*VerifyResponse, error) {
	var res *VerifyResponse
	err := c.transportClient.Call(endpoints.VerifyIdentity, &VerifyRequest{
		Type:        request.Type,
		Value:       request.Value,
		ExtraFields: request.ExtraFields,
	}, &res)

	if err != nil {
		return nil, err
	}

	return &VerifyResponse{
		ActionId: res.ActionId,
	}, nil
}

func (c *Client) ConfirmIdentity(request *ConfirmRequest) (*ConfirmResponse, error) {
	var res *ConfirmResponse

	err := c.transportClient.Call(endpoints.ConfirmIdentity, &ConfirmRequest{
		ActionId:         request.ActionId,
		ConfirmationCode: request.ConfirmationCode,
		Params: ValidationTokenParams{
			CountToLive: request.Params.CountToLive,
			TimeToLive:  request.Params.TimeToLive,
		},
	}, &res)

	if err != nil {
		return nil, err
	}

	return &ConfirmResponse{
		Type:            res.Type,
		Value:           res.Value,
		ValidationToken: res.ValidationToken,
	}, nil
}

func (c *Client) ValidateIdentity(request *ValidateRequest) error {
	return c.transportClient.Call(endpoints.ValidateIdentity, &ValidateRequest{
		Type:            request.Type,
		Value:           request.Value,
		ValidationToken: request.ValidationToken,
	}, nil)
}

func (c *Client) convertToCardAndValidate(response *CardResponse) (*Card, error) {

	card, err := response.ToCard()

	if err != nil {
		return nil, err
	}

	if c.cardsValidator != nil {
		ok, err := c.cardsValidator.Validate(card)
		if !ok {
			return nil, err
		}
	}
	return card, nil
}
