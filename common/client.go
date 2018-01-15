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

package common

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/pkg/errors"
)

type HttpClient interface {
	Do(*http.Request) (*http.Response, error)
}

type VirgilHttpClient struct {
	Client  HttpClient
	Address string
}

func (vc *VirgilHttpClient) Send(method string, url string, payload interface{}, respObj interface{}) error {
	var body []byte
	var err error
	if payload != nil {
		body, err = json.Marshal(payload)
		if err != nil {
			return errors.Wrap(err, "VirgilHttpClient.Send: marshal payload")
		}
	}
	req, err := http.NewRequest(method, vc.Address+url, bytes.NewReader(body))
	if err != nil {
		return errors.Wrap(err, "VirgilHttpClient.Send: new request")
	}
	client := vc.getHttpClient()
	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "VirgilHttpClient.Send: send request")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return EntityNotFoundErr
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "VirgilHttpClient.Send: read response body")
	}

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		if respObj != nil {
			err = json.Unmarshal(respBody, respObj)
			if err != nil {
				return errors.Wrap(err, "VirgilHttpClient.Send: unmarshal response object")
			}
		}
		return nil
	}
	var virgilErr VirgilAPIError
	err = json.Unmarshal(respBody, &virgilErr)
	if err != nil {
		return errors.Wrap(err, "VirgilHttpClient.Send: unmarshal response object")
	}
	return virgilErr
}

func (vc *VirgilHttpClient) getHttpClient() HttpClient {
	if vc.Client != nil {
		return vc.Client
	}
	return http.DefaultClient
}
