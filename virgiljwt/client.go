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

package virgiljwt

import (
	"time"

	"github.com/dgrijalva/jwt-go"
	"gopkg.in/virgil.v6/crypto-api"
)

var DefaultTTL uint = 15

func Make(crypto cryptoapi.Crypto, sk cryptoapi.PrivateKey, publicKeyID string, accID string) JWTClient {
	return JWTClient{
		crypto:    crypto,
		secretKey: sk,
		publicKeyID: publicKeyID,
		accID:     accID,
	}
}

type JWTClient struct {
	crypto    cryptoapi.Crypto
	secretKey cryptoapi.PrivateKey
	publicKeyID string
	accID     string
}

type JWTParam struct {
	AppID   string
	TTL      uint      // count in minutes
	IssuedAt time.Time //UTC date

}

func (c JWTClient) Generate(p JWTParam) (string, error) {
	if p.IssuedAt.Before(time.Now()) {
		p.IssuedAt = time.Now()
	}
	if p.TTL == 0 {
		p.TTL = DefaultTTL
	}

	token := jwt.NewWithClaims(makeVirgilSigningMethod(), jwt.MapClaims{
		"iss":    "virgil-" + p.AppID,
		"sub":    "identity-"+c.accID,
		"iat":    p.IssuedAt.UTC().Unix(),
		"exp":    p.IssuedAt.Add(time.Duration(p.TTL) * time.Minute).UTC().Unix(),
	})

	token.Header["cty"] = "virgil-jwt;v=1"

	token.Header["kid"] = c.publicKeyID

	return token.SignedString(secretKey{Crypto: c.crypto, Key: c.secretKey})
}
