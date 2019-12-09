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
	"time"

	"github.com/VirgilSecurity/virgil-sdk-go/crypto"
)

type CardManagerOption func(c *CardManager)

func CardManagerSetModelSigner(ms ModelSigner) CardManagerOption {
	return func(c *CardManager) {
		c.modelSigner = ms
	}
}

func CardManagerSetCrypto(cc crypto.CardCrypto) CardManagerOption {
	return func(c *CardManager) {
		c.crypto = cc
	}
}

func CardManagerSetCardVerifier(cv CardVerifier) CardManagerOption {
	return func(c *CardManager) {
		c.cardVerifier = cv
	}
}

func CardManagerSetCardClient(cc CardClient) CardManagerOption {
	return func(c *CardManager) {
		c.cardClient = cc
	}
}

func CardManagerSetSignCallback(callback func(model *RawSignedModel) (signedCard *RawSignedModel, err error)) CardManagerOption {
	return func(c *CardManager) {
		c.signCallback = callback
	}
}

type CardManager struct {
	modelSigner         ModelSigner
	crypto              crypto.CardCrypto
	accessTokenProvider AccessTokenProvider
	cardVerifier        CardVerifier
	cardClient          CardClient
	signCallback        func(model *RawSignedModel) (signedCard *RawSignedModel, err error)
}

func NewCardManager(accessTokenProvider AccessTokenProvider, options ...CardManagerOption) *CardManager {
	cm := &CardManager{
		crypto:              defaultCardCrypto,
		accessTokenProvider: accessTokenProvider,
		cardClient:          NewCardsClient(),
	}

	for _, opt := range options {
		opt(cm)
	}

	return cm
}

func (c *CardManager) GenerateRawCard(cardParams *CardParams) (*RawSignedModel, error) {
	model, err := GenerateRawCard(c.crypto, cardParams, time.Now().UTC().Truncate(time.Second))
	if err != nil {
		return nil, err
	}

	err = c.modelSigner.SelfSign(model, cardParams.PrivateKey, cardParams.ExtraFields)
	if err != nil {
		return nil, err
	}
	return model, nil
}

func (c *CardManager) PublishRawCard(rawSignedModel *RawSignedModel) (card *Card, err error) {
	model := &RawCardContent{}
	if err = ParseSnapshot(rawSignedModel.ContentSnapshot, &model); err != nil {
		return nil, err
	}

	tokenContext := &TokenContext{Service: "cards", Operation: "publish", Identity: model.Identity}
	token, err := c.accessTokenProvider.GetToken(tokenContext)
	if err != nil {
		return nil, err
	}

	if c.signCallback != nil {
		if rawSignedModel, err = c.signCallback(rawSignedModel); err != nil {
			return nil, err
		}
	}
	rawCard, err := c.cardClient.PublishCard(rawSignedModel, token.String())
	if err != nil {
		return nil, err
	}

	card, err = ParseRawCard(c.crypto, rawCard, false)
	if err != nil {
		return nil, err
	}

	if err := c.verifyCards(card); err != nil {
		return nil, err
	}
	return card, nil
}

func (c *CardManager) PublishCard(cardParams *CardParams) (*Card, error) {
	rawSignedModel, err := c.GenerateRawCard(cardParams)
	if err != nil {
		return nil, err
	}
	return c.PublishRawCard(rawSignedModel)
}

func (c *CardManager) GetCard(cardID string) (*Card, error) {
	tokenContext := &TokenContext{Identity: "my_default_identity", Operation: "get"}
	token, err := c.accessTokenProvider.GetToken(tokenContext)
	if err != nil {
		return nil, err
	}

	rawCard, outdated, err := c.cardClient.GetCard(cardID, token.String())
	if err != nil {
		return nil, err
	}

	card, err := ParseRawCard(c.crypto, rawCard, outdated)
	if err != nil {
		return nil, err
	}
	err = c.verifyCards(card)
	if err != nil {
		return nil, err
	}
	return card, nil
}

func (c *CardManager) RevokeCard(cardID string) error {
	tokenContext := &TokenContext{Operation: "delete", Service: "cards"}
	token, err := c.accessTokenProvider.GetToken(tokenContext)
	if err != nil {
		return err
	}

	return c.cardClient.RevokeCard(cardID, token.String())
}

func (c *CardManager) SearchCards(identity string) (Cards, error) {
	tokenContext := &TokenContext{Identity: "my_default_identity", Operation: "search"}
	token, err := c.accessTokenProvider.GetToken(tokenContext)
	if err != nil {
		return nil, err
	}

	rawCards, err := c.cardClient.SearchCards(identity, token.String())
	if err != nil {
		return nil, err
	}

	cards, err := ParseRawCards(c.crypto, rawCards...)
	if err != nil {
		return nil, err
	}
	err = c.verifyCards(cards...)
	if err != nil {
		return nil, err
	}
	return LinkCards(cards...), nil
}

func (c *CardManager) ExportCardAsRawCard(card *Card) (*RawSignedModel, error) {
	return ParseCard(c.crypto, card)
}

func (c *CardManager) ExportCardAsString(card *Card) (string, error) {
	model, err := ParseCard(c.crypto, card)
	if err != nil {
		return "", err
	}
	return model.ExportAsBase64EncodedString()
}

func (c *CardManager) ExportCardAsJson(card *Card) (string, error) {
	model, err := ParseCard(c.crypto, card)
	if err != nil {
		return "", err
	}
	return model.ExportAsJson()
}

func (c *CardManager) ImportCardFromString(str string) (*Card, error) {
	model, err := GenerateRawSignedModelFromString(str)
	if err != nil {
		return nil, err
	}

	return c.ImportCard(model)
}

func (c *CardManager) ImportCardFromJson(json string) (*Card, error) {
	model, err := GenerateRawSignedModelFromJson(json)
	if err != nil {
		return nil, err
	}

	return c.ImportCard(model)
}

func (c *CardManager) ImportCard(model *RawSignedModel) (*Card, error) {
	cards, err := ParseRawCards(c.crypto, model)
	if err != nil {
		return nil, err
	}
	return cards[0], nil
}

func (c *CardManager) verifyCards(cards ...*Card) error {
	if c.cardVerifier == nil {
		return nil
	}

	for _, card := range cards {
		if err := c.cardVerifier.VerifyCard(card); err != nil {
			return err
		}
	}
	return nil
}
