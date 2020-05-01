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
	"encoding/base64"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"

	"github.com/VirgilSecurity/virgil-sdk-go/v6/errors"
	"github.com/VirgilSecurity/virgil-sdk-go/v6/session"
)

func initCardManager() (*CardManager, error) {
	return initCardManagerWithIdentityName("default_identity")
}
func initCardManagerWithIdentityName(identityName string) (*CardManager, error) {
	appKeyID := os.Getenv("TEST_APP_KEY_ID")
	if appKeyID == "" {
		return nil, xerrors.New("TEST_APP_KEY_ID is required")
	}
	appKeySource := os.Getenv("TEST_APP_KEY")
	if appKeySource == "" {
		return nil, xerrors.New("TEST_APP_KEY is required")
	}
	appKey, err := cryptoNative.ImportPrivateKey([]byte(appKeySource))
	if err != nil {
		return nil, xerrors.Errorf("Cannot import appplication key: %w", err)
	}

	appID := os.Getenv("TEST_APP_ID")
	if appID == "" {
		return nil, xerrors.New("TEST_APP_ID is required")
	}

	var virgilCardVerifierOptions []VirgilCardVerifierOption
	if serviceKey := os.Getenv("TEST_SERVICE_KEY"); serviceKey != "" {
		virgilCardVerifierOptions = append(virgilCardVerifierOptions, VirgilCardVerifierSetCardsServicePublicKey(serviceKey))
	}

	var cardClientOptions []CardClientOption
	if os.Getenv("TEST_ADDRESS") != "" {
		cardClientOptions = append(cardClientOptions, SetCardClientURL(os.Getenv("TEST_ADDRESS")))
	}

	generator := session.JwtGenerator{
		AppKey:            appKey,
		AppKeyID:          appKeyID,
		AppID:             appID,
		AccessTokenSigner: &session.VirgilAccessTokenSigner{Crypto: cryptoNative},
		TTL:               time.Minute,
	}

	return NewCardManager(
		session.NewGeneratorJwtProvider(
			generator,
			session.SetGeneratorJwtProviderDefaultIdentity(identityName),
		),
		CardManagerSetCardClient(NewCardsClient(cardClientOptions...)),
		CardManagerSetCardVerifier(NewVirgilCardVerifier(virgilCardVerifierOptions...)),
	), nil
}

func TestCardManager_Integration_Publish_Get_Search(t *testing.T) {
	var expectedError = &errors.VirgilAPIError{Code: 10001, Message: "Requested card entity not found."}

	manager, err := initCardManager()
	require.NoError(t, err)

	card, err := manager.GetCard(randomHexString())
	require.Nil(t, card)
	require.True(t, xerrors.Is(err, expectedError), err.Error())

	card, err = PublishCard(t, manager, "Alice-"+randomString(), "", "")
	require.NoError(t, err)
	card, err = manager.GetCard(card.Id)
	require.NoError(t, err)
	require.NotNil(t, card)

	cards, err := manager.SearchCards(card.Identity)

	require.NoError(t, err)
	require.True(t, len(cards) > 0)

	cards, err = manager.SearchCards(randomString())
	require.True(t, len(cards) == 0)
	require.NoError(t, err)
}

func TestCardManager_Integration_Publish_Get_Search_Types(t *testing.T) {
	manager, err := initCardManager()
	require.NoError(t, err)

	name1 := "Alice-" + randomString()
	name2 := "Bob-" + randomString()
	type1 := randomString()
	type2 := randomString()

	_, err = PublishCard(t, manager, name1, type1, "")
	require.NoError(t, err)

	_, err = PublishCard(t, manager, name1, type2, "")
	require.NoError(t, err)

	_, err = PublishCard(t, manager, name2, type1, "")
	require.NoError(t, err)

	_, err = PublishCard(t, manager, name2, type2, "")
	require.NoError(t, err)

	cards, err := manager.SearchCardsWithTypes([]string{name1}, type1, randomString())

	require.NoError(t, err)
	require.Equal(t, 1, len(cards))
	require.Equal(t, type1, cards[0].CardType)

	cards, err = manager.SearchCardsWithTypes([]string{name1}, type2, randomString())

	require.NoError(t, err)
	require.Equal(t, 1, len(cards))
	require.Equal(t, type2, cards[0].CardType)

	cards, err = manager.SearchCardsWithTypes([]string{name1, name2}, type1, randomString())

	require.NoError(t, err)
	require.Equal(t, 2, len(cards))
	require.Equal(t, type1, cards[0].CardType)
	require.Equal(t, type1, cards[1].CardType)

	cards, err = manager.SearchCardsWithTypes([]string{name1}, type2, type1)

	require.NoError(t, err)
	require.Equal(t, 2, len(cards))
	require.Equal(t, name1, cards[0].Identity)
	require.Equal(t, name1, cards[1].Identity)

	cards, err = manager.SearchCardsWithTypes([]string{name2}, type1, type2, randomString())

	require.NoError(t, err)
	require.Equal(t, 2, len(cards))
	require.Equal(t, name2, cards[0].Identity)
	require.Equal(t, name2, cards[1].Identity)

	cards, err = manager.SearchCardsWithTypes([]string{name2, name1}, type2, type1, randomString())

	require.NoError(t, err)
	require.Equal(t, 4, len(cards))

	cards, err = manager.SearchCardsWithTypes([]string{name1, name2})

	require.NoError(t, err)
	require.Equal(t, 4, len(cards))

	cards, err = manager.SearchCardsWithTypes([]string{name1, name2}, randomString())
	require.Equal(t, 0, len(cards))
	require.NoError(t, err)
}

func TestCardManager_Integration_Publish_Replace(t *testing.T) {
	manager, err := initCardManager()
	require.NoError(t, err)

	oldCard, err := PublishCard(t, manager, "Alice-"+randomString(), "", "")
	require.NoError(t, err)

	newCard, err := PublishCard(t, manager, oldCard.Identity, "", oldCard.Id)
	require.NoError(t, err)
	require.NotNil(t, newCard)

	oldCard, err = manager.GetCard(oldCard.Id)
	require.NoError(t, err)
	require.NotNil(t, oldCard)
	require.True(t, oldCard.IsOutdated)
}

func TestCardManager_Integration_Publish_Revoke(t *testing.T) {
	manager, err := initCardManager()
	require.NoError(t, err)

	card, err := PublishCard(t, manager, "Alice-"+randomString(), "", "")
	require.NoError(t, err)
	require.NotNil(t, card)

	card, err = manager.GetCard(card.Id)
	require.NoError(t, err)
	require.NotNil(t, card)
	require.False(t, card.IsOutdated)

	err = manager.RevokeCard(card.Id)
	require.NoError(t, err)
}

func TestCardManager_Integration_Publish_Replace_Link(t *testing.T) {
	manager, err := initCardManager()
	require.NoError(t, err)

	identity := "Alice-" + randomString()

	var card *Card
	for i := 0; i < 3; i++ { //3 branches of 3 cards each
		prev := ""
		for j := 0; j < 3; j++ {
			card, err = PublishCard(t, manager, identity, "", prev)
			require.NoError(t, err)
			prev = card.Id
		}
	}

	cards, err := manager.SearchCards(identity)
	require.NoError(t, err)

	require.True(t, len(cards) == 3)

	for _, card := range cards {
		current := card
		for i := 0; i < 2; i++ {
			require.True(t, current.PreviousCard != nil)
			require.True(t, current.PreviousCard.Id == current.PreviousCardId)
			current = current.PreviousCard
		}
	}
}

func PublishCard(t *testing.T, manager *CardManager, identity, cardType, previousCardID string) (*Card, error) {
	key, err := cryptoNative.GenerateKeypair()
	require.NoError(t, err)

	cardParams := &CardParams{
		PrivateKey:     key,
		Identity:       identity,
		CardType:       cardType,
		PreviousCardId: previousCardID,
		ExtraFields:    map[string]string{"key": "value"},
	}

	card, err := manager.PublishCard(cardParams)
	require.NoError(t, err)
	require.Equal(t, card.Identity, cardParams.Identity)
	return card, err
}

func randomHexString() string {
	var buf [32]byte
	rand.Read(buf[:])
	return hex.EncodeToString(buf[:])
}

func randomString() string {
	var buf [8]byte
	rand.Read(buf[:])
	return base64.StdEncoding.EncodeToString(buf[:])
}
