// +build integration

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
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/xerrors"

	"github.com/VirgilSecurity/virgil-sdk-go/errors"
	"github.com/VirgilSecurity/virgil-sdk-go/session"
)

func initCardManager() (*CardManager, error) {
	return initCardManagerWithIdentityName("default_identity")
}
func initCardManagerWithIdentityName(identityName string) (*CardManager, error) {
	apiKeyID := os.Getenv("TEST_API_KEY_ID")
	if apiKeyID == "" {
		return nil, xerrors.New("TEST_API_KEY_ID is required")
	}
	apiKeySource := os.Getenv("TEST_API_KEY")
	if apiKeySource == "" {
		return nil, xerrors.New("TEST_API_KEY is required")
	}
	apiKey, err := cryptoNative.ImportPrivateKey([]byte(apiKeySource))
	if err != nil {
		return nil, xerrors.Errorf("Cannot import API private key: %w", err)
	}

	appID := os.Getenv("TEST_APP_ID")
	if appID == "" {
		return nil, xerrors.New("TEST_APP_ID is required")
	}

	var virgilCardVerifierOptions []VirgilCardVerifierOption
	if serviceKey := os.Getenv("TEST_SERVICE_KEY"); serviceKey != "" {
		virgilCardVerifierOptions = append(virgilCardVerifierOptions, VirgilCardVerifierSetCardsServicePublicKey(serviceKey))
	}

	cardClientOptions := []CardClientOption{}
	if os.Getenv("TEST_ADDRESS") != "" {
		cardClientOptions = append(cardClientOptions, SetCardClientURL(os.Getenv("TEST_ADDRESS")))
	}

	generator := session.JwtGenerator{
		ApiKey:                 apiKey,
		ApiPublicKeyIdentifier: apiKeyID,
		AppID:                  appID,
		AccessTokenSigner:      session.VirgilAccessTokenSigner{Crypto: cryptoNative},
		TTL:                    time.Minute,
	}

	return NewCardManager(session.NewGeneratorJwtProvider(generator, nil, identityName),
		CardManagerSetCardClient(NewCardsClient(cardClientOptions...)),
		CardManagerSetCardVerifier(NewVirgilCardVerifier(virgilCardVerifierOptions...)),
	), nil
}

func TestCardManager_Integration_Publish_Get_Search(t *testing.T) {
	var expectedError = errors.VirgilAPIError{Code: 10001, Message: "Requested card entity not found."}

	manager, err := initCardManager()
	assert.NoError(t, err)

	card, err := manager.GetCard(randomString())
	assert.Nil(t, card)
	assert.True(t, xerrors.Is(err, expectedError), err.Error())

	card, err = PublishCard(t, manager, "Alice-"+randomString(), "")
	assert.NoError(t, err)
	card, err = manager.GetCard(card.Id)
	assert.NoError(t, err)
	assert.NotNil(t, card)

	cards, err := manager.SearchCards(card.Identity)

	assert.NoError(t, err)
	assert.True(t, len(cards) > 0)

	cards, err = manager.SearchCards(randomString())
	assert.True(t, len(cards) == 0)
	assert.NoError(t, err)
}

func TestCardManager_Integration_Publish_Replace(t *testing.T) {
	manager, err := initCardManager()
	assert.NoError(t, err)

	oldCard, err := PublishCard(t, manager, "Alice-"+randomString(), "")
	assert.NoError(t, err)

	newCard, err := PublishCard(t, manager, oldCard.Identity, oldCard.Id)
	assert.NoError(t, err)
	assert.NotNil(t, newCard)

	oldCard, err = manager.GetCard(oldCard.Id)
	assert.NoError(t, err)
	assert.NotNil(t, oldCard)
	assert.True(t, oldCard.IsOutdated)
}

func TestCardManager_Integration_Publish_Revoke(t *testing.T) {
	manager, err := initCardManager()
	assert.NoError(t, err)

	card, err := PublishCard(t, manager, "Alice-"+randomString(), "")
	assert.NoError(t, err)
	assert.NotNil(t, card)

	card, err = manager.GetCard(card.Id)
	assert.NoError(t, err)
	assert.NotNil(t, card)
	assert.False(t, card.IsOutdated)

	manager, err = initCardManagerWithIdentityName(card.Identity)
	assert.NoError(t, err)

	err = manager.RevokeCard(card.Id)
	assert.NoError(t, err)
}

func TestCardManager_Integration_Publish_Replace_Link(t *testing.T) {
	manager, err := initCardManager()
	assert.NoError(t, err)

	identity := "Alice-" + randomString()

	var card *Card
	for i := 0; i < 3; i++ { //3 branches of 3 cards each
		prev := ""
		for j := 0; j < 3; j++ {
			card, err = PublishCard(t, manager, identity, prev)
			assert.NoError(t, err)
			prev = card.Id
		}
	}

	cards, err := manager.SearchCards(identity)
	assert.NoError(t, err)

	assert.True(t, len(cards) == 3)

	for _, card := range cards {
		current := card
		for i := 0; i < 2; i++ {
			assert.True(t, current.PreviousCard != nil)
			assert.True(t, current.PreviousCard.Id == current.PreviousCardId)
			current = current.PreviousCard
		}
	}
}

func PublishCard(t *testing.T, manager *CardManager, identity string, previousCardID string) (*Card, error) {
	key, err := cryptoNative.GenerateKeypair()
	assert.NoError(t, err)

	cardParams := &CardParams{
		PrivateKey:     key,
		Identity:       identity,
		PreviousCardId: previousCardID,
		ExtraFields:    map[string]string{"key": "value"},
	}

	card, err := manager.PublishCard(cardParams)
	assert.NoError(t, err)
	assert.Equal(t, card.Identity, cardParams.Identity)
	return card, err
}

func randomString() string {
	var buf [32]byte
	rand.Read(buf[:])
	return hex.EncodeToString(buf[:])
}
