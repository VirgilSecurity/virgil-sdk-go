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

package session

import (
	"errors"
	"strings"

	"github.com/VirgilSecurity/virgil-sdk-go/v6/crypto"
)

type JwtVerifier struct {
	appPublicKey      crypto.PublicKey
	appPublicKeyID    string
	accessTokenSigner AccessTokenSigner
}

func NewJwtVerifier(appPublicKey crypto.PublicKey, appPublicKeyID string, accessTokenSigner AccessTokenSigner) *JwtVerifier {
	v := &JwtVerifier{
		accessTokenSigner: accessTokenSigner,
		appPublicKeyID:    appPublicKeyID,
		appPublicKey:      appPublicKey,
	}
	if err := v.Validate(); err != nil {
		panic(err)
	}
	return v
}

func (j *JwtVerifier) VerifyToken(jwtToken *Jwt) error {
	if jwtToken == nil {
		return ErrJWTTokenIsMandatory
	}

	if jwtToken.HeaderContent.AppKeyID != j.appPublicKeyID ||
		jwtToken.HeaderContent.Algorithm != j.accessTokenSigner.GetAlgorithm() ||
		jwtToken.HeaderContent.ContentType != VirgilContentType ||
		jwtToken.HeaderContent.Type != JwtType {
		return ErrJWTInvalid
	}

	return jwtToken.verify(j.accessTokenSigner, j.appPublicKey)
}

func (j *JwtVerifier) Validate() error {
	if j.accessTokenSigner == nil {
		return errors.New("JwtVerifier: access token signer is not set")
	}

	if j.appPublicKey == nil {
		return errors.New("JwtVerifier: api public key is not set")
	}

	if strings.Replace(j.appPublicKeyID, " ", "", -1) == "" {
		return errors.New("JwtVerifier: api public key id is not set")
	}
	return nil
}
