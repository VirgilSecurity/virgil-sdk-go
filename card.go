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
	"github.com/pkg/errors"
	"gopkg.in/virgil.v4/virgilcrypto"
)

//Card is basically a public key + meta information like identity, its type and so on
//The ID of a card is the hash of its Snapshot (json encoded basic fields)
type Card struct {
	ID           string
	Snapshot     []byte
	Identity     string
	IdentityType string
	PublicKey    virgilcrypto.PublicKey
	Scope        Enum
	Data         map[string]string
	DeviceInfo   DeviceInfo
	CreatedAt    string
	CardVersion  string
	Signatures   map[string][]byte
	Relations    map[string][]byte
}

//DeviceInfo is for device type & its concrete name, for example model
type DeviceInfo struct {
	Device     string `json:"device"`
	DeviceName string `json:"device_name"`
}

//Encrypt encrypts data for a given card using ECIES
func (c *Card) Encrypt(data []byte) ([]byte, error) {
	return Crypto().Encrypt(data, c.PublicKey)
}

//SignThenEncrypt encrypts data for a given card using ECIES and signs the plaintext
func (c *Card) SignThenEncrypt(data []byte, signerKey virgilcrypto.PrivateKey) ([]byte, error) {
	return Crypto().SignThenEncrypt(data, signerKey, c.PublicKey)
}

//Verify verifies a signature of data using the provided Card. Must return non nil error when the result is false
func (c *Card) Verify(data, signature []byte) error {
	return Crypto().Verify(data, signature, c.PublicKey)
}

func (c *Card) ToRequest() (*SignableRequest, error) {
	if len(c.Snapshot) == 0 {
		return nil, errors.New("The card has no snapshot")
	}
	request := &SignableRequest{
		Snapshot: c.Snapshot,
		Meta: RequestMeta{
			Signatures: c.Signatures,
		},
	}
	return request, nil
}
