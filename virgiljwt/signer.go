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
	"github.com/dgrijalva/jwt-go"

	cryptoapi "gopkg.in/virgil.v6/crypto-api"
)

//
// Virgil signing constants.
//
const (
	VirgilSigningAlgorithm = "VIRGIL"
)

//
// init registers Virgil Security token validator.
//
func init() {
	jwt.RegisterSigningMethod(VirgilSigningAlgorithm, makeVirgilSigningMethod)
}

//
// GetVirgilSigningMethod returns an instance of Virgil signing method.
//
func makeVirgilSigningMethod() jwt.SigningMethod {
	return new(virgilSigner)
}

type secretKey struct {
	Crypto cryptoapi.Crypto
	Key    cryptoapi.PrivateKey
}

type publicKey struct {
	Crypto cryptoapi.Crypto
	Key    cryptoapi.PublicKey
}

//
// virgilSigner is a Virgil Security implementation for the token signing.
//
type virgilSigner struct{}

//
// Verify performs token verification.
// Expects key to be virgilcrypto.PublicKey
//
func (s *virgilSigner) Verify(signingString, signature string, key interface{}) error {
	pk, ok := key.(publicKey)
	if !ok {
		return jwt.ErrInvalidKeyType
	}

	decodedSignature, err := jwt.DecodeSegment(signature)
	if nil != err {
		return ErrSignatureDecode
	}

	err = pk.Crypto.VerifySignature([]byte(signingString), decodedSignature, pk.Key)
	if err != nil {
		return ErrSignatureIsInvalid
	}

	return nil
}

//
// Sign performs token signing.
// Expects key to be virgilcrypto.PrivateKey instance.
//
func (s *virgilSigner) Sign(signingString string, key interface{}) (string, error) {
	sk, ok := key.(secretKey)
	if !ok {
		return "", jwt.ErrInvalidKeyType
	}

	signature, err := sk.Crypto.Sign([]byte(signingString), sk.Key)
	if nil != err {
		return "", err
	}

	return jwt.EncodeSegment(signature), nil
}

//
// Alg returns signer algorithm name.
//
func (s *virgilSigner) Alg() string {
	return VirgilSigningAlgorithm
}
