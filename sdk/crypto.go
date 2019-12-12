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
	"github.com/VirgilSecurity/virgil-sdk-go/crypto"
)

var (
	DefaultCrypto Crypto = crypto.NewVirgilCrypto()
)

type Crypto interface {
	Sign(data []byte, privateKey crypto.PrivateKey) ([]byte, error)
	VerifySignature(data []byte, signature []byte, publicKey crypto.PublicKey) error
	ExportPublicKey(publicKey crypto.PublicKey) ([]byte, error)
	ImportPublicKey(publicKeySrc []byte) (crypto.PublicKey, error)
	Hash(data []byte, t crypto.HashType) ([]byte, error)
}

type CardCrypto struct {
	Crypto Crypto
}

func (c *CardCrypto) GenerateSignature(data []byte, key crypto.PrivateKey) ([]byte, error) {
	return c.getCrypto().Sign(data, key)
}

func (c *CardCrypto) VerifySignature(data []byte, signature []byte, key crypto.PublicKey) error {
	return c.getCrypto().VerifySignature(data, signature, key)
}

func (c *CardCrypto) ExportPublicKey(key crypto.PublicKey) ([]byte, error) {
	return c.getCrypto().ExportPublicKey(key)
}

func (c *CardCrypto) ImportPublicKey(data []byte) (crypto.PublicKey, error) {
	return c.getCrypto().ImportPublicKey(data)
}

func (c *CardCrypto) GenerateSHA512(data []byte) ([]byte, error) {
	return c.Crypto.Hash(data, crypto.Sha512)
}

func (c *CardCrypto) getCrypto() Crypto {
	if c.Crypto != nil {
		return c.Crypto
	}
	return DefaultCrypto
}
