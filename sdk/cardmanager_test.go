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
 */

package sdk

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"testing"
	"time"

	"crypto/rand"
	"encoding/hex"

	"github.com/stretchr/testify/assert"
	virgil "gopkg.in/virgil.v5"
	"gopkg.in/virgil.v5/cryptoimpl"
	"gopkg.in/virgil.v5/errors"
)

var (
	crypto     = &cryptoimpl.VirgilCrypto{}
	cardCrypto = &cryptoimpl.CardCrypto{Crypto: crypto}
)

func initCardManager() (*CardManager, error) {
	apiUrl := os.Getenv("TEST_ADDRESS")
	accID := os.Getenv("TEST_ACC_ID")
	if accID == "" {
		return nil, errors.New("TEST_ACC_ID is required")
	}
	apiKeySource := os.Getenv("TEST_API_KEY")
	if apiKeySource == "" {
		return nil, errors.New("TEST_API_KEY is required")
	}
	apiKey, err := crypto.ImportPrivateKey([]byte(apiKeySource), "")
	if err != nil {
		return nil, errors.Wrap(err, "Cannot import API private key: ")
	}

	appID := os.Getenv("TEST_APP_ID")
	if appID == "" {
		return nil, errors.New("TEST_APP_ID is required")
	}

	verifier, err := NewVirgilCardVerifier(cardCrypto, true, true)

	if err != nil {
		panic(err)
	}

	generator := NewJwtGenerator(apiKey, accID, cryptoimpl.NewVirgilAccessTokenSigner(), appID, time.Minute*10)
	cardsClient := NewCardsClient(apiUrl)
	cardsClient.HttpClient = &DebugClient{}
	params := &CardManagerParams{
		Crypto:              cardCrypto,
		ApiUrl:              apiUrl,
		CardVerifier:        verifier,
		ModelSigner:         NewModelSigner(cardCrypto),
		AccessTokenProvider: NewGeneratorJwtProvider(generator, nil, ""),
		CardClient:          cardsClient,
	}
	return NewCardManager(params)
}

func TestCardManager_Integration(t *testing.T) {

	manager, err := initCardManager()
	assert.NoError(t, err)

	kp, err := crypto.GenerateKeypair()
	assert.NoError(t, err)

	cardParams := &CardParams{
		PublicKey:  kp.PublicKey(),
		PrivateKey: kp.PrivateKey(),
		Identity:   "Alice-" + randomString(),
	}

	card, err := manager.PublishCard(cardParams)
	assert.NoError(t, err)
	assert.Equal(t, card.Identity, cardParams.Identity)

	card, err = manager.GetCard(card.Identifier)
	assert.NoError(t, err)
	assert.NotNil(t, card)

	cards, err := manager.SearchCards(card.Identity)

	assert.NoError(t, err)
	assert.True(t, len(cards) > 0)

}

type DebugClient struct {
	Client virgil.HttpClient
}

func (c *DebugClient) Do(req *http.Request) (*http.Response, error) {
	var (
		body []byte
		err  error
	)
	fmt.Println("Request:", req.Method, req.URL.String())

	if len(req.Header) > 0 {
		fmt.Println("Header:")
		for key := range req.Header {
			fmt.Println("\t", key, ":", req.Header.Get(key))
		}
		fmt.Println("")
	}
	if req.Body != nil {
		body, err = ioutil.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("Cannot read body request: %v", err)
		}
		fmt.Println("Body:", string(body))
		req.Body = ioutil.NopCloser(bytes.NewReader(body))
	}

	resp, err := c.getClient().Do(req)
	if err != nil {
		return resp, err
	}
	fmt.Println("Response:", resp.StatusCode)
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("Cannot read body request: %v", err)
	}
	fmt.Println("Body:", string(body))
	resp.Body = ioutil.NopCloser(bytes.NewReader(body))

	fmt.Println("")
	return resp, nil
}

func (c *DebugClient) getClient() virgil.HttpClient {
	if c.Client == nil {
		return http.DefaultClient
	}
	return c.Client
}

func randomString() string {
	buf := make([]byte, 10)
	rand.Read(buf)
	return hex.EncodeToString(buf)
}
