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
	"time"

	"github.com/VirgilSecurity/virgil-sdk-go/crypto"
)

type AccessTokenSigner interface {
	GenerateTokenSignature(data []byte, privateKey crypto.PrivateKey) ([]byte, error)
	VerifyTokenSignature(data []byte, signature []byte, publicKey crypto.PublicKey) error
	GetAlgorithm() string
}

type JwtGenerator struct {
	AppKey            crypto.PrivateKey
	AppKeyID          string
	AppID             string
	AccessTokenSigner AccessTokenSigner
	TTL               time.Duration
}

func (j *JwtGenerator) Validate() error {
	if j.AppKey == nil {
		return errors.New("JwtGenerator: api private key is not set")
	}
	if strings.Replace(j.AppKeyID, " ", "", -1) == "" {
		return errors.New("JwtGenerator: api public key identifier is not set")
	}

	if strings.Replace(j.getAccessTokenSigner().GetAlgorithm(), " ", "", -1) == "" {
		return errors.New("JwtGenerator: access token signer is not set")
	}
	return nil
}

func (j *JwtGenerator) GenerateToken(identity string, additionalData map[string]interface{}) (*Jwt, error) {
	if strings.Replace(identity, " ", "", -1) == "" {
		return nil, ErrIdentityIsMandatory
	}

	issuedAt := time.Now().UTC().Truncate(time.Second)
	expiresAt := issuedAt.Add(j.getTTL())

	h := JwtHeaderContent{
		Algorithm:   j.getAccessTokenSigner().GetAlgorithm(),
		APIKeyID:    j.AppKeyID,
		ContentType: VirgilContentType,
		Type:        JwtType,
	}
	b := JwtBodyContent{
		AppID:          j.AppID,
		Identity:       identity,
		Issuer:         IssuerPrefix + j.AppID,
		Subject:        IdentityPrefix + identity,
		IssuedAt:       issuedAt.UTC().Unix(),
		ExpiresAt:      expiresAt.UTC().Unix(),
		AdditionalData: additionalData,
	}
	jwt := NewJwt(h, b)
	if err := jwt.Sign(j.getAccessTokenSigner(), j.AppKey); err != nil {
		return nil, err
	}

	return jwt, nil
}

func (j JwtGenerator) getAccessTokenSigner() AccessTokenSigner {
	if j.AccessTokenSigner == nil {
		return &VirgilAccessTokenSigner{}
	}
	return j.AccessTokenSigner
}

func (j JwtGenerator) getTTL() time.Duration {
	if j.TTL == 0 {
		return time.Hour
	}
	return j.TTL
}
