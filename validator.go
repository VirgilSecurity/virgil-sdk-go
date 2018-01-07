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

package virgilcards

import "gopkg.in/virgil.v6/crypto-api"

type SignerInfo struct {
	CardID    string
	PublicKey cryptoapi.PublicKey
}

const (
	VirgilCardServiceCardId    = "e680bef87ba75d331b0a02bfa6a20f02eb5c5ba9bc96fc61ca595404b10026f4"
	VirgilCardServicePublicKey = "MCowBQYDK2VwAyEAhvwMS/KZMd0hkZop+oLEh9ZdlSByj7r0lFzqS57rvLA="
)

var VirgilSignerInfo = SignerInfo{
	CardID:    VirgilCardServiceCardId,
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
	WhiteList             []SignerInfo
	IgnoreSelfSignature   bool
	IgnoreVirgilSignature bool
}

func (v *ExtendedValidator) Validate(crypto cryptoapi.Crypto, card Card) (err error) {
	if !v.IgnoreSelfSignature {
		err = v.checkSign(crypto, card, SignerInfo{CardID: card.ID, PublicKey: card.PublicKey}, SignerTypeSelf)
		if err != nil {
			return err
		}
	}
	if !v.IgnoreVirgilSignature {
		err = v.checkSign(crypto, card, VirgilSignerInfo, SignerTypeVirgil)
		if err != nil {
			return err
		}
	}
	if len(v.WhiteList) == 0 {
		return nil
	}
	for _, signer := range v.WhiteList {
		err = v.checkSign(crypto, card, signer, SignerTypeExtra)
		if err == CardValidationExpectedSignerWasNotFoundErr {
			continue
		}
		if err != nil {
			return err
		}
		return nil
	}
	return CardValidationExpectedSignerWasNotFoundErr
}

func (v *ExtendedValidator) checkSign(crypto cryptoapi.Crypto, card Card, signer SignerInfo, signerType SignerType) error {
	if len(card.Signature) == 0 {
		return CardValidationExpectedSignerWasNotFoundErr
	}
	for _, s := range card.Signature {
		if s.SignerCardId == signer.CardID {
			if s.SignerType != signerType {
				return CardValidationSignerTypeIncorrectErr
			}
			snapshot := append(card.Snapshot, s.Snapshot...)
			err := crypto.VerifySignature(crypto.CalculateFingerprint(snapshot), s.Signature, signer.PublicKey)
			if err != nil {
				return err
			} else {
				return nil
			}
		}
	}
	return CardValidationExpectedSignerWasNotFoundErr
}
