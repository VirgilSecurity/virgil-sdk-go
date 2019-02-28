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
	"gopkg.in/virgil.v5/cryptoapi"
)

type testCredentials struct {
	*VerifierCredentials
	PrivateKey cryptoapi.PrivateKey
}

func TestWhitelist(t *testing.T) {

	pk, cardCreds := makeRandomCredentials()

	var creds []*testCredentials
	for i := 0; i < 5; i++ {
		pk, cred := makeRandomCredentials()
		creds = append(creds, &testCredentials{VerifierCredentials: cred, PrivateKey: pk})
	}

	var wl []*Whitelist

	wl = addWhitelist(wl, creds[0], creds[1])

	wl = addWhitelist(wl, creds[2])

	model, err := GenerateRawCard(cardCrypto, &CardParams{
		Identity:   cardCreds.Signer,
		PrivateKey: pk,
		PublicKey:  cardCreds.PublicKey,
	}, time.Now())

	modelSigner := NewModelSigner(cardCrypto)
	modelSigner.SelfSign(model, pk, map[string]string{
		"a": "b",
		"b": "c",
		"x": "y",
		"z": cardCreds.Signer,
	})

	addSign(t, model, creds[0])
	addRawSign(t, model, creds[1])
	addRawSign(t, model, creds[2])

	verifier, err := NewVirgilCardVerifier(cardCrypto, true, false, wl...)

	card, err := ParseRawCard(cardCrypto, model, false)

	require.NoError(t, err)

	//check default case
	err = verifier.VerifyCard(card)
	require.NoError(t, err)

	//check that everything is ok if at least one signature in whitelist is valid
	wl[0].VerifierCredentials[0] = creds[4].VerifierCredentials

	err = verifier.VerifyCard(card)
	require.NoError(t, err)

	//Check that verification fails if no signature exists for whitelist
	wl = addWhitelist(wl, creds[3])
	verifier.SetWhitelists(wl)

	err = verifier.VerifyCard(card)
	require.Error(t, err)

	err, ok := ToCardVerifierError(err)
	require.Error(t, err)
	require.True(t, ok)

	//empty whitelist must fail
	verifier.SetWhitelists([]*Whitelist{{}})
	err = verifier.VerifyCard(card)
	require.Error(t, err)

	err, ok = ToCardVerifierError(err)
	require.Error(t, err)
	require.True(t, ok)

}

func addRawSign(t *testing.T, model *RawSignedModel, credentials *testCredentials) {

	modelSigner := &ModelSigner{Crypto: cardCrypto}

	snapshot := make([]byte, 129)
	rand.Read(snapshot)

	err := modelSigner.SignRaw(model, credentials.Signer, credentials.PrivateKey, snapshot)

	require.NoError(t, err)
}

func addSign(t *testing.T, model *RawSignedModel, credentials *testCredentials) {

	modelSigner := &ModelSigner{Crypto: cardCrypto}

	err := modelSigner.Sign(model, credentials.Signer, credentials.PrivateKey, map[string]string{
		"a": "b",
		"b": "c",
		"x": "y",
		"z": credentials.Signer,
	})

	require.NoError(t, err)
}

func addWhitelist(wl []*Whitelist, creds ...*testCredentials) []*Whitelist {

	twl := &Whitelist{}

	for _, cred := range creds {
		twl.VerifierCredentials = append(twl.VerifierCredentials, cred.VerifierCredentials)
	}

	wl = append(wl, twl)
	return wl
}

func makeRandomCredentials() (cryptoapi.PrivateKey, *VerifierCredentials) {
	kp, err := crypto.GenerateKeypair()
	if err != nil {
		panic(err)
	}

	id := make([]byte, 32)
	rand.Read(id)

	return kp.PrivateKey(), &VerifierCredentials{
		Signer:    hex.EncodeToString(id),
		PublicKey: kp.PublicKey(),
	}
}
