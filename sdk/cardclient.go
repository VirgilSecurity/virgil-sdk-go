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
	"log"
	"net/http"

	"sync"

	"encoding/hex"

	"github.com/lestrrat-go/backoff"
	"gopkg.in/virgil.v5/common"
	"gopkg.in/virgil.v5/errors"
)

type CardClient struct {
	ServiceURL          string
	VirgilHttpClient    *common.VirgilHttpClient
	HttpClient          common.HttpClient
	AccessTokenProvider AccessTokenProvider
	once                sync.Once
}

func NewCardsClient(serviceURL string, provider AccessTokenProvider) *CardClient {
	return &CardClient{ServiceURL: serviceURL, AccessTokenProvider: provider}
}

func (c *CardClient) PublishCard(rawCard *RawSignedModel, tokenContext *TokenContext) (*RawSignedModel, error) {
	var returnedRawCard *RawSignedModel
	_, err := c.sendWithRetry(http.MethodPost, "/card/v5", tokenContext, rawCard, &returnedRawCard)
	return returnedRawCard, err
}

func (c *CardClient) SearchCards(identity string, tokenContext *TokenContext) ([]*RawSignedModel, error) {
	var rawCards []*RawSignedModel
	_, err := c.sendWithRetry(http.MethodPost, "/card/v5/actions/search", tokenContext, map[string]string{"identity": identity}, &rawCards)
	if err != nil {
		return nil, err
	}

	return rawCards, err
}

func (c *CardClient) GetCard(cardId string) (*RawSignedModel, bool, error) {

	const (
		SupersededCardIDHTTPHeader      = "X-Virgil-Is-Superseeded"
		SupersededCardIDHTTPHeaderValue = "true"
	)

	if _, err := hex.DecodeString(cardId); err != nil || len(cardId) != 64 {
		return nil, false, errors.New("invalid card id")
	}

	var rawCard *RawSignedModel
	headers, err := c.sendWithRetry(http.MethodGet, "/card/v5/"+cardId, &TokenContext{Identity: "my_default_identity", Operation: "get"}, nil, &rawCard)

	var outdated bool
	if headers != nil {
		outdated = headers.Get(SupersededCardIDHTTPHeader) == SupersededCardIDHTTPHeaderValue
	}

	return rawCard, outdated, err
}

func (c *CardClient) send(method string, url string, token string, payload interface{}, respObj interface{}) (headers http.Header, err error) {
	client := c.getVirgilClient()
	headers, httpCode, err := client.Send(method, url, token, payload, respObj)
	if err != nil {
		if apiErr, ok := err.(common.VirgilAPIError); ok {
			return headers, errors.NewServiceError(apiErr.Code, httpCode, apiErr.Message)
		}
		return headers, errors.NewServiceError(0, httpCode, err.Error())
	}
	return headers, nil
}

func (c *CardClient) sendWithRetry(method string, url string, tokenContext *TokenContext, payload interface{}, respObj interface{}) (headers http.Header, err error) {
	b, done := policy.Start(context.Background())
	defer done()

	forceReload := false
	var token AccessToken
	for backoff.Continue(b) {
		tokenContext.ForceReload = forceReload
		token, err = c.AccessTokenProvider.GetToken(tokenContext)
		if err != nil {
			return nil, err
		}

		headers, err = c.send(method, url, token.String(), payload, respObj)
		if err == nil {
			return
		}
		forceReload = false

		var sdkErr errors.SDKError
		var res bool
		if sdkErr, res = errors.ToSdkError(err); !res {
			return
		}

		if sdkErr.HTTPErrorCode() >= 200 && sdkErr.HTTPErrorCode() < 400 {
			return
		}

		if sdkErr.HTTPErrorCode() >= 400 && sdkErr.HTTPErrorCode() < 500 {
			if sdkErr.HTTPErrorCode() == 401 && sdkErr.ServiceErrorCode() == 20304 {
				forceReload = true
				log.Printf("rertying because of auth %s\n", url)
				continue
			}
			return
		}

		if sdkErr.HTTPErrorCode() >= 500 && sdkErr.HTTPErrorCode() < 600 {
			log.Printf("rertying %s\n", url)
			continue
		}
		return

	}
	return
}

func (c *CardClient) getUrl() string {
	if c.ServiceURL != "" {
		return c.ServiceURL
	}
	return "https://api.virgilsecurity.com"
}

func (c *CardClient) getHttpClient() common.HttpClient {
	if c.HttpClient != nil {
		return c.HttpClient
	}
	return http.DefaultClient
}

func (c *CardClient) getVirgilClient() *common.VirgilHttpClient {

	c.once.Do(func() {
		if c.VirgilHttpClient == nil {
			c.VirgilHttpClient = &common.VirgilHttpClient{
				Address: c.getUrl(),
				Client:  c.getHttpClient(),
			}
		}
	})

	return c.VirgilHttpClient
}
