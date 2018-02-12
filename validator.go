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

package virgil

import "gopkg.in/virgil.v5/cryptoapi"

type VerifierCredentials struct {
	Signer    string
	PublicKey cryptoapi.PublicKey
}

const (
	VirgilCardServiceSigner    = "virgil"
	VirgilCardServicePublicKey = "MCowBQYDK2VwAyEAr0rjTWlCLJ8q9em0og33grHEh/3vmqp0IewosUaVnQg="
)

/*
var VirgilSignerInfo = &VerifierCredentials{
	Signer:    VirgilCardServiceSigner,
	PublicKey: loadServicePublicKey(),
}

func loadServicePublicKey() cryptoapi.PublicKey {
	key, err := DefaultCrypto.ImportPublicKey([]byte(VirgilCardServicePublicKey))
	if err != nil {
		panic(err)
	}
	return key
}

type ExtendedValidator struct {
	WhiteList             []*Whitelist
	IgnoreSelfSignature   bool
	IgnoreVirgilSignature bool
}

func (v *ExtendedValidator) Validate(crypto cryptoapi.CardCrypto, card *Card) (err error) {
	if !v.IgnoreSelfSignature {
		err = v.checkSign(crypto, card, &VerifierCredentials{Signer: SignerTypeSelf, PublicKey: card.PublicKey})
		if err != nil {
			return err
		}
	}
	if !v.IgnoreVirgilSignature {
		err = v.checkSign(crypto, card, VirgilSignerInfo)
		if err != nil {
			return err
		}
	}
	if len(v.WhiteList) == 0 {
		return nil
	}

	for _, whiteList := range v.WhiteList {

		ok := false
		var lastErr error
		for _, cred := range whiteList.VerifierCredentials {
			err = v.checkSign(crypto, card, cred)
			if err == nil {
				ok = true
				break
			} else {
				lastErr = err
			}
		}

		if !ok {
			if lastErr == nil {
				lastErr = CardValidationExpectedSignerWasNotFoundErr
			}

			return lastErr
		}
	}
	return nil
}

func (v *ExtendedValidator) checkSign(crypto cryptoapi.CardCrypto, card *Card, verifier *VerifierCredentials) error {
	if len(card.Signature) == 0 {
		return CardValidationExpectedSignerWasNotFoundErr
	}
	for _, s := range card.Signature {
		if s.Signer == verifier.Signer {
			snapshot := append(card.Snapshot, s.Snapshot...)
			err := crypto.VerifySignature(snapshot, s.Signature, verifier.PublicKey)
			if err != nil {
				return err
			} else {
				return nil
			}
		}
	}
	return CardValidationExpectedSignerWasNotFoundErr
}
*/
