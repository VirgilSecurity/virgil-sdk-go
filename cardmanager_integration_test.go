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

package virgilcards_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"testing"

	"gopkg.in/virgil.v5"
	"gopkg.in/virgil.v5/crypto-api"
	"gopkg.in/virgil.v5/crypto-native"
	"gopkg.in/virgil.v5/virgiljwt"
)

var cardsManager virgilcards.CardsManager
var appCardID string
var appSK cryptoapi.PrivateKey

type StaticTokenClient struct {
	Token  string
	Client virgilcards.HttpClient
}

func (c StaticTokenClient) Do(req *http.Request) (resp *http.Response, err error) {
	req.Header.Add("Authorization", "Virgil "+c.Token)
	return c.Client.Do(req)
}

func TestMain(m *testing.M) {

	address := os.Getenv("TEST_ADDRESS")
	accID := os.Getenv("TEST_ACC_ID")
	if accID == "" {
		log.Fatal("TEST_ACC_ID is required")
	}
	apiKeySource := os.Getenv("TEST_API_KEY")
	if apiKeySource == "" {
		log.Fatal("TEST_API_KEY is required")
	}
	apiKey, err := cryptonative.DefaultCrypto.ImportPrivateKey([]byte(apiKeySource), "")
	if err != nil {
		log.Fatal("Cannot import API private key: ", err)
	}

	apiID := os.Getenv("TEST_API_ID")
	if accID == "" {
		log.Fatal("TEST_API_ID is required")
	}

	appCardID = os.Getenv("TEST_APP_ID")
	if appCardID == "" {
		log.Fatal("TEST_APP_ID is required")
	}

	appSKSource := os.Getenv("TEST_APP_SECRET_KEY")
	if appSKSource == "" {
		log.Fatal("TEST_APP_SECRET_KEY is required")
	}
	appSKPassword := os.Getenv("TEST_APP_SECRET_KEY_PASSWORD")
	appSK, err = cryptonative.DefaultCrypto.ImportPrivateKey([]byte(appSKSource), appSKPassword)
	if err != nil {
		log.Fatal("Cannot import private key: ", err)
	}

	jwtMaker := virgiljwt.Make(virgilcards.DefaultCrypto, apiKey, apiID)
	token, err := jwtMaker.Generate(virgiljwt.JWTParam{AppID: appCardID, Identity: accID})
	if err != nil {
		log.Fatal("Cannot generate JWT token: ", err)
	}

	fmt.Println(token)
	cardsManager = virgilcards.CardsManager{
		ApiUrl:     address,
		HttpClient: StaticTokenClient{Token: token, Client: &DebugClient{}},
		Validator:  &virgilcards.ExtendedValidator{},
	}

	os.Exit(m.Run())
}

func TestCardManager_PublishCard_ReturnCard(t *testing.T) {
	kp, err := cryptonative.DefaultCrypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := cardsManager.GenerateCSR(virgilcards.CSRParams{
		Identity:   genRandomID(),
		PrivateKey: kp.PrivateKey(),
		PublicKey:  kp.PublicKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	err = cardsManager.SignCSR(&csr, virgilcards.CSRSignParams{
		SignerCardId:     appCardID,
		SignerPrivateKey: appSK,
		SignerType:       virgilcards.SignerTypeApplication,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = cardsManager.PublishCard(csr)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCardManager_GetCard_ReturnCard(t *testing.T) {
	kp, err := cryptonative.DefaultCrypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := cardsManager.GenerateCSR(virgilcards.CSRParams{
		Identity:   genRandomID(),
		PrivateKey: kp.PrivateKey(),
		PublicKey:  kp.PublicKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	err = cardsManager.SignCSR(&csr, virgilcards.CSRSignParams{
		SignerCardId:     appCardID,
		SignerPrivateKey: appSK,
		SignerType:       virgilcards.SignerTypeApplication,
	})
	if err != nil {
		t.Fatal(err)
	}

	expectedCard, err := cardsManager.PublishCard(csr)
	if err != nil {
		t.Fatal(err)
	}
	_, err = cardsManager.GetCard(expectedCard.ID)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCardManager_SearchCard_ReturnCard(t *testing.T) {
	kp, err := cryptonative.DefaultCrypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := cardsManager.GenerateCSR(virgilcards.CSRParams{
		Identity:   genRandomID(),
		PrivateKey: kp.PrivateKey(),
		PublicKey:  kp.PublicKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	err = cardsManager.SignCSR(&csr, virgilcards.CSRSignParams{
		SignerCardId:     appCardID,
		SignerPrivateKey: appSK,
		SignerType:       virgilcards.SignerTypeApplication,
	})
	if err != nil {
		t.Fatal(err)
	}

	expectedCard, err := cardsManager.PublishCard(csr)
	if err != nil {
		t.Fatal(err)
	}

	_, err = cardsManager.SearchCards(expectedCard.Identity)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCardManager_RevokeCard_ReturnCard(t *testing.T) {
	kp, err := cryptonative.DefaultCrypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := cardsManager.GenerateCSR(virgilcards.CSRParams{
		Identity:   genRandomID(),
		PrivateKey: kp.PrivateKey(),
		PublicKey:  kp.PublicKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	err = cardsManager.SignCSR(&csr, virgilcards.CSRSignParams{
		SignerCardId:     appCardID,
		SignerPrivateKey: appSK,
		SignerType:       virgilcards.SignerTypeApplication,
	})
	if err != nil {
		t.Fatal(err)
	}

	revokedCard, err := cardsManager.PublishCard(csr)
	if err != nil {
		t.Fatal(err)
	}

	kp, err = cryptonative.DefaultCrypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	csr, err = cardsManager.GenerateCSR(virgilcards.CSRParams{
		Identity:       revokedCard.Identity,
		PreviousCardID: revokedCard.ID,
		PrivateKey:     kp.PrivateKey(),
		PublicKey:      kp.PublicKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	err = cardsManager.SignCSR(&csr, virgilcards.CSRSignParams{
		SignerCardId:     appCardID,
		SignerPrivateKey: appSK,
		SignerType:       virgilcards.SignerTypeApplication,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = cardsManager.PublishCard(csr)
	if err != nil {
		t.Fatal(err)
	}

	_, err = cardsManager.GetCard(revokedCard.ID)
	if err == nil {
		t.Fatal(err)
	}
}

func genRandomID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

type DebugClient struct {
	Client virgilcards.HttpClient
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

func (c *DebugClient) getClient() virgilcards.HttpClient {
	if c.Client == nil {
		return http.DefaultClient
	}
	return c.Client
}
