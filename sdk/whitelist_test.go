/*
 * // Copyright (C) 2015-2018 Virgil Security Inc.
 * //
 * // Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 * //
 * // All rights reserved.
 * //
 * // Redistribution and use in source and binary forms, with or without
 * // modification, are permitted provided that the following conditions
 * // are met:
 * //
 * //   (1) Redistributions of source code must retain the above copyright
 * //   notice, this list of conditions and the following disclaimer.
 * //
 * //   (2) Redistributions in binary form must reproduce the above copyright
 * //   notice, this list of conditions and the following disclaimer in
 * //   the documentation and/or other materials provided with the
 * //   distribution.
 * //
 * //   (3) Neither the name of the copyright holder nor the names of its
 * //   contributors may be used to endorse or promote products derived
 * //   from this software without specific prior written permission.
 * //
 * // THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * // IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * // WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * // DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * // INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * // (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * // SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * // HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * // STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * // IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * // POSSIBILITY OF SUCH DAMAGE.
 */

package sdk

import "gopkg.in/virgil.v5/cryptoimpl"

//var crypto = &cryptoimpl.CardCrypto{Crypto: &cryptoimpl.VirgilCrypto{}}

type testCredentials struct {
	*VerifierCredentials
	PrivateKey cryptoimpl.PrivateKey
}

/*func TestWhitelist(t *testing.T) {

	pk, cardCreds := makeRandomCredentials()

	var creds []*testCredentials
	for i := 0; i < 5; i++ {
		pk, cred := makeRandomCredentials()
		creds = append(creds, &testCredentials{VerifierCredentials: cred, PrivateKey: pk})
	}

	var wl []*Whitelist

	wl = addWhitelist(wl, creds[0], creds[1])

	wl = addWhitelist(wl, creds[2])

	cardsManager := &CardsManager{}
	csr, err := cardsManager.GenerateCSR(&CSRParams{
		PrivateKey: pk,
		PublicKey:  cardCreds.PublicKey,
		Identity:   cardCreds.Signer,
	})
	assert.NoError(t, err)

	addSign(t, csr, creds[0])
	addSign(t, csr, creds[1])
	addSign(t, csr, creds[2])

	validator := &ExtendedValidator{IgnoreSelfSignature: true, IgnoreVirgilSignature: true, WhiteList: wl}

	card := &Card{
		Snapshot: csr.Snapshot,
	}

	for _, sig := range csr.Signatures {
		card.Signature = append(card.Signature, &CardSignature{
			Signature: sig.Signature,
			Snapshot:  sig.ExtraFields,
			Signer:    sig.Signer,
		})
	}

	//check default case
	err = validator.Validate(crypto, card)
	assert.NoError(t, err)

	//check that everything is ok if at least one signature in whitelist is valid
	wl[0].VerifierCredentials[0] = creds[4].VerifierCredentials

	err = validator.Validate(crypto, card)
	assert.NoError(t, err)

	//Check that verification fails if no signature exists for whitelist
	wl = addWhitelist(wl, creds[3])
	validator.WhiteList = wl

	err = validator.Validate(crypto, card)
	assert.Error(t, err)

	//empty whitelist must fail
	validator.WhiteList = []*Whitelist{{}}
	err = validator.Validate(crypto, card)
	assert.Error(t, err)

}
func addSign(t *testing.T, csr *CSR, credentials *testCredentials) {
	err := csr.Sign(crypto, &CSRSignParams{
		Signer:           credentials.Signer,
		SignerPrivateKey: credentials.PrivateKey,
		ExtraFields: map[string]string{
			"a": "b",
			"b": "c",
			"x": "y",
			"z": credentials.Signer,
		},
	})
	assert.NoError(t, err)
}

func addWhitelist(wl []*Whitelist, creds ...*testCredentials) []*Whitelist {

	twl := &Whitelist{}

	for _, cred := range creds {
		twl.VerifierCredentials = append(twl.VerifierCredentials, cred.VerifierCredentials)
	}

	wl = append(wl, twl)
	return wl
}

func makeRandomCredentials() (cryptoimpl.PrivateKey, *VerifierCredentials) {
	kp, err := crypto.Crypto.GenerateKeypair()
	if err != nil {
		panic(err)
	}

	id := make([]byte, 32)
	rand.Read(id)

	return kp.PrivateKey(), &VerifierCredentials{
		Signer:    hex.EncodeToString(id),
		PublicKey: kp.PublicKey(),
	}
}*/
