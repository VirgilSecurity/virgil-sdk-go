/*
 * Copyright (C) 2015-2018 Virgil Security Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   (1) Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 *   (2) Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 *   (3) Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

package sdk

import (
	"context"
	"encoding/hex"
	"net/http"

	"github.com/VirgilSecurity/virgil-sdk-go/v6"
	"github.com/VirgilSecurity/virgil-sdk-go/v6/common/client"
	"github.com/VirgilSecurity/virgil-sdk-go/v6/errors"
)

type cardClientOption struct {
	serviceURL string
	httpClient *http.Client
}

type CardClientOption func(c *cardClientOption)

func SetCardClientURL(serviceURL string) CardClientOption {
	return func(c *cardClientOption) {
		c.serviceURL = serviceURL
	}
}

func SetCardClientHTTPClient(httpClient *http.Client) CardClientOption {
	return func(c *cardClientOption) {
		c.httpClient = httpClient
	}
}

type CardClient struct {
	client *client.Client
}

func NewCardsClient(options ...CardClientOption) *CardClient {
	o := &cardClientOption{
		serviceURL: "https://api.virgilsecurity.com",
		httpClient: client.DefaultHTTPClient,
	}
	for _, opt := range options {
		opt(o)
	}

	return &CardClient{
		client: client.NewClient(o.serviceURL,
			client.HTTPClient(o.httpClient),
			client.VirgilProduct("sdk", virgil.Version),
		),
	}
}

func (c *CardClient) PublishCard(rawCard *RawSignedModel, token string) (*RawSignedModel, error) {
	resp, err := c.client.Send(context.TODO(), &client.Request{
		Method:   http.MethodPost,
		Endpoint: "/card/v5",
		Payload:  rawCard,
		Header:   c.makeHeader(token),
	})

	if err != nil {
		return nil, errors.NewSDKError(err, "action", "CardClient.PublishCard")
	}

	returnedRawCard := new(RawSignedModel)
	if err = resp.Unmarshal(returnedRawCard); err != nil {
		return nil, errors.NewSDKError(err, "action", "CardClient.PublishCard")
	}

	return returnedRawCard, nil
}

func (c *CardClient) SearchCards(identity string, token string) ([]*RawSignedModel, error) {
	resp, err := c.client.Send(context.TODO(), &client.Request{
		Method:   http.MethodPost,
		Endpoint: "/card/v5/actions/search",
		Payload:  map[string]string{"identity": identity},
		Header:   c.makeHeader(token),
	})
	if err != nil {
		return nil, errors.NewSDKError(err, "action", "CardClient.SearchCards")
	}

	var rawCards []*RawSignedModel
	if err = resp.Unmarshal(&rawCards); err != nil {
		return nil, errors.NewSDKError(err, "action", "CardClient.SearchCards")
	}

	return rawCards, nil
}

func (c *CardClient) RevokeCard(cardID string, token string) error {
	if _, err := hex.DecodeString(cardID); err != nil || len(cardID) != 64 {
		return errors.NewSDKError(ErrInvalidCardID, "action", "CardClient.RevokeCard")
	}

	_, err := c.client.Send(context.TODO(), &client.Request{
		Method:   http.MethodPost,
		Endpoint: "/card/v5/actions/revoke/" + cardID,
		Payload:  nil,
		Header:   c.makeHeader(token),
	})

	return errors.NewSDKError(err, "action", "CardClient.RevokeCard")
}

func (c *CardClient) GetCard(cardID string, token string) (*RawSignedModel, bool, error) {
	const (
		SupersededCardIDHTTPHeader      = "X-Virgil-Is-Superseeded"
		SupersededCardIDHTTPHeaderValue = "true"
	)

	if _, err := hex.DecodeString(cardID); err != nil || len(cardID) != 64 {
		return nil, false, errors.NewSDKError(ErrInvalidCardID, "action", "CardClient.GetCard", "card_id", cardID)
	}

	resp, err := c.client.Send(context.TODO(), &client.Request{
		Method:   http.MethodGet,
		Endpoint: "/card/v5/" + cardID,
		Payload:  nil,
		Header:   c.makeHeader(token),
	})
	if err != nil {
		return nil, false, errors.NewSDKError(err, "action", "CardClient.GetCard", "card_id", cardID)
	}
	rawCard := new(RawSignedModel)
	if err = resp.Unmarshal(rawCard); err != nil {
		return nil, false, errors.NewSDKError(err, "action", "CardClient.GetCard", "card_id", cardID)
	}

	outdated := resp.Header.Get(SupersededCardIDHTTPHeader) == SupersededCardIDHTTPHeaderValue
	return rawCard, outdated, nil
}

func (c *CardClient) makeHeader(token string) http.Header {
	return http.Header{
		"Authorization": []string{"Virgil " + token},
	}
}
