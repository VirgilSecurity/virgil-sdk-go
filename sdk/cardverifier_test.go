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
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/VirgilSecurity/virgil-sdk-go/v6/crypto"
)

type testCredentials struct {
	VerifierCredentials *VerifierCredentials
	PrivateKey          crypto.PrivateKey
}

func TestAllowList(t *testing.T) {
	const credsCount = 5
	creds := make([]testCredentials, 5)
	for i := 0; i < credsCount; i++ {
		pk, cred := makeRandomCredentials()
		creds[i] = testCredentials{VerifierCredentials: cred, PrivateKey: pk}
	}

	pk, cardCreds := makeRandomCredentials()
	model, err := GenerateRawCard(cryptoNative, &CardParams{
		Identity:   cardCreds.Signer,
		PrivateKey: pk,
	}, time.Now())
	require.NoError(t, err)

	var modelSigner ModelSigner // NewModelSigner(cardCrypto)
	err = modelSigner.SelfSign(model, pk, map[string]string{
		"a": "b",
		"b": "c",
		"x": "y",
		"z": cardCreds.Signer,
	})
	require.NoError(t, err)

	addSign(t, model, creds[0])
	addRawSign(t, model, creds[1])
	addRawSign(t, model, creds[2])

	verifier := NewVirgilCardVerifier(
		VirgilCardVerifierSetCrypto(cryptoNative),
		VirgilCardVerifierDisableVirgilSignature(),
		VirgilCardVerifierAddAllowList(NewAllowList(creds[0].VerifierCredentials, creds[1].VerifierCredentials)),
		VirgilCardVerifierAddAllowList(NewAllowList(creds[2].VerifierCredentials)),
	)

	card, err := ParseRawCard(cryptoNative, model, false)
	require.NoError(t, err)

	// check default case
	err = verifier.VerifyCard(card)
	require.NoError(t, err)

	// check that everything is ok if at least one signature in allow list is valid
	// creds[4] doesn't exist
	verifier = NewVirgilCardVerifier(
		VirgilCardVerifierSetCrypto(cryptoNative),
		VirgilCardVerifierDisableVirgilSignature(),
		VirgilCardVerifierAddAllowList(NewAllowList(creds[4].VerifierCredentials, creds[1].VerifierCredentials)),
	)

	err = verifier.VerifyCard(card)
	require.NoError(t, err)

	// Check that verification fails if no signature exists for allow list
	// creds[3] doesn't exist
	verifier = NewVirgilCardVerifier(
		VirgilCardVerifierSetCrypto(cryptoNative),
		VirgilCardVerifierDisableVirgilSignature(),
		VirgilCardVerifierAddAllowList(NewAllowList(creds[2].VerifierCredentials)),
		VirgilCardVerifierAddAllowList(NewAllowList(creds[3].VerifierCredentials)),
	)

	err = verifier.VerifyCard(card)
	require.Error(t, err)
}

func addRawSign(t *testing.T, model *RawSignedModel, credentials testCredentials) {
	modelSigner := &ModelSigner{Crypto: cryptoNative}

	snapshot := make([]byte, 129)
	_, err := rand.Read(snapshot)
	require.NoError(t, err)

	err = modelSigner.SignRaw(model, credentials.VerifierCredentials.Signer, credentials.PrivateKey, snapshot)
	require.NoError(t, err)
}

func addSign(t *testing.T, model *RawSignedModel, credentials testCredentials) {
	modelSigner := &ModelSigner{Crypto: cryptoNative}

	err := modelSigner.Sign(model, credentials.VerifierCredentials.Signer, credentials.PrivateKey, map[string]string{
		"a": "b",
		"b": "c",
		"x": "y",
		"z": credentials.VerifierCredentials.Signer,
	})

	require.NoError(t, err)
}

func makeRandomCredentials() (crypto.PrivateKey, *VerifierCredentials) {
	key, err := cryptoNative.GenerateKeypair()
	if err != nil {
		panic(err)
	}

	id := make([]byte, 32)
	_, err = rand.Read(id)
	if err != nil {
		panic(err)
	}

	return key, &VerifierCredentials{
		Signer:    hex.EncodeToString(id),
		PublicKey: key.PublicKey(),
	}
}
