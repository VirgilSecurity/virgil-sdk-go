/*
Copyright (C) 2016-2017 Virgil Security Inc.

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
)

var (
	ErrNotFound            = transport.ErrNotFound
	DefaultServiceBaseURLs = map[transport.ServiceType]string{
		Cardservice:     "https://cards.virgilsecurity.com",
		ROCardService:   "https://cards-ro.virgilsecurity.com",
		IdentityService: "https://identity.virgilsecurity.com",
		VRAService:      "https://ra.virgilsecurity.com",
	}
)

// ClientTransport sets card service protocol for a Virgil client
//
func ClientTransport(transportClient transport.Client) func(*Client) {
	return func(client *Client) {
		client.TransportClient = transportClient
	}
}

// ClientCardsValidator sets custom card validaor for a Virgil client
//
func ClientCardsValidator(validator CardsValidator) func(*Client) {
	return func(client *Client) {
		client.CardsValidator = validator
	}
}

// NewClient create a new instance of Virgil client
func NewClient(accessToken string, opts ...func(*Client)) (*Client, error) {
	v, err := MakeDefaultCardsValidator()
	if err != nil {
		return nil, err
	}

	c := &Client{
		TransportClient: transport.NewTransportClient(DefaultHTTPEndpoints, DefaultServiceBaseURLs),
		CardsValidator:  v,
	}

	for _, option := range opts {
		option(c)
	}

	c.TransportClient.SetToken(accessToken)
	return c, nil
}

// A Client manages communication with Virgil Security API.
type Client struct {
	TransportClient transport.Client
	CardsValidator  CardsValidator
}

// GetCard return a card from Virgil Read Only Card service
func (c *Client) GetCard(id string) (*Card, error) {
	var res *CardResponse
	err := c.TransportClient.Call(GetCard, nil, &res, id)
	if err != nil {
		return nil, err
	}
	return c.ConvertToCardAndValidate(res)
}

// CreateCard posts card create request to server where it checks signatures and adds it
func (c *Client) CreateCard(request *SignableRequest) (*Card, error) {
	if request == nil || len(request.Snapshot) == 0 || len(request.Meta.Signatures) == 0 {
		return nil, errors.New("request is empty or does not contain any signatures")
	}
	var res *CardResponse
	err := c.TransportClient.Call(CreateCard, request, &res)

	if err != nil {
		return nil, err
	}
	return c.ConvertToCardAndValidate(res)
}

// RevokeCard deletes card from server
func (c *Client) RevokeCard(request *SignableRequest) error {
	if request == nil {
		return errors.New("request is nil")
	}
	req := &RevokeCardRequest{}
	err := json.Unmarshal(request.Snapshot, req)
	if err != nil {
		return errors.Wrap(err, "")
	}

	return c.TransportClient.Call(RevokeCard, request, nil, req.ID)
}

func (c *Client) SearchCards(criteria *Criteria) ([]*Card, error) {
	if criteria == nil || len(criteria.Identities) == 0 {
		return nil, errors.New("search criteria cannot be empty")
	}
	var res []*CardResponse
	err := c.TransportClient.Call(SearchCards, criteria, &res)
	if err != nil {
		return nil, err
	}

	var cards []*Card
	for _, v := range res {
		card, err := c.ConvertToCardAndValidate(v)
		if err != nil {
			return nil, err
		}
		cards = append(cards, card)
	}
	return cards, nil
}

func (c *Client) VerifyIdentity(request *VerifyRequest) (*VerifyResponse, error) {
	if request == nil {
		return nil, errors.New("request is nil")
	}
	var res *VerifyResponse
	err := c.TransportClient.Call(VerifyIdentity, request, &res)

	if err != nil {
		return nil, err
	}

	return res, nil
}

func (c *Client) ConfirmIdentity(request *ConfirmRequest) (*ConfirmResponse, error) {
	if request == nil {
		return nil, errors.New("request is nil")
	}
	var res *ConfirmResponse

	err := c.TransportClient.Call(ConfirmIdentity, request, &res)

	if err != nil {
		return nil, err
	}

	return res, nil
}

func (c *Client) ValidateIdentity(request *ValidateRequest) error {
	if request == nil {
		return errors.New("request is nil")
	}
	return c.TransportClient.Call(ValidateIdentity, request, nil)
}

// AddRelation adds signature of the card signer trusts
func (c *Client) AddRelation(request *SignableRequest) (*Card, error) {
	if request == nil || len(request.Snapshot) == 0 || len(request.Meta.Signatures) != 1 {
		return nil, errors.New("request must not be empty and must contain exactly 1 relation signature")
	}

	var id string
	for k := range request.Meta.Signatures {
		id = k
	}

	var res *CardResponse
	err := c.TransportClient.Call(AddRelation, request, &res, id)

	if err != nil {
		return nil, err
	}
	return c.ConvertToCardAndValidate(res)
}

// AddRelation adds signature of the card signer trusts
func (c *Client) DeleteRelation(request *SignableRequest) (*Card, error) {
	if request == nil || len(request.Snapshot) == 0 || len(request.Meta.Signatures) != 1 {
		return nil, errors.New("request must not be empty and must contain exactly 1 signature")
	}

	var id string
	for k := range request.Meta.Signatures {
		id = k
	}

	var res *CardResponse
	err := c.TransportClient.Call(DeleteRelation, request, &res, id)

	if err != nil {
		return nil, err
	}
	return c.ConvertToCardAndValidate(res)
}

func (c *Client) ConvertToCardAndValidate(response *CardResponse) (*Card, error) {

	card, err := response.ToCard()

	if err != nil {
		return nil, err
	}

	if c.CardsValidator != nil {
		ok, err := c.CardsValidator.Validate(card)
		if !ok {
			return nil, err
		}
	}
	return card, nil
}
