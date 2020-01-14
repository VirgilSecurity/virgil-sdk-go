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
	"github.com/VirgilSecurity/virgil-sdk-go/v6/crypto"
	"github.com/VirgilSecurity/virgil-sdk-go/v6/errors"
)

type CardVerifier interface {
	VerifyCard(card *Card) error
}

const (
	virgilCardServicePublicKey = "MCowBQYDK2VwAyEAljOYGANYiVq1WbvVvoYIKtvZi2ji9bAhxyu6iV/LF8M="
)

type VirgilCardVerifierOption func(v *VirgilCardVerifier)

func VirgilCardVerifierSetCrypto(c Crypto) VirgilCardVerifierOption {
	return func(v *VirgilCardVerifier) {
		v.crypto = &CardCrypto{c}
	}
}

func VirgilCardVerifierDisableSelfSignature() VirgilCardVerifierOption {
	return func(v *VirgilCardVerifier) {
		v.verifySelfSignature = false
	}
}

func VirgilCardVerifierDisableVirgilSignature() VirgilCardVerifierOption {
	return func(v *VirgilCardVerifier) {
		v.verifyVirgilSignature = false
	}
}

func VirgilCardVerifierAddWhitelist(wl Whitelist) VirgilCardVerifierOption {
	return func(v *VirgilCardVerifier) {
		v.whitelists = append(v.whitelists, wl)
	}
}

func VirgilCardVerifierSetCardsServicePublicKey(ks string) VirgilCardVerifierOption {
	return func(v *VirgilCardVerifier) {
		v.virgilPublicKeySource = ks
	}
}

type VirgilCardVerifier struct {
	crypto                *CardCrypto
	verifySelfSignature   bool
	verifyVirgilSignature bool
	whitelists            []Whitelist
	virgilPublicKey       crypto.PublicKey

	// virgilPublicKeySource is used to update Virgil Cards service public key
	// it is needed only in the init step another cases use virgilPublicKey
	virgilPublicKeySource string
}

func NewVirgilCardVerifier(options ...VirgilCardVerifierOption) *VirgilCardVerifier {
	verifier := &VirgilCardVerifier{
		crypto:                &CardCrypto{},
		verifySelfSignature:   true,
		verifyVirgilSignature: true,

		virgilPublicKeySource: virgilCardServicePublicKey,
	}

	for _, opt := range options {
		opt(verifier)
	}

	if verifier.verifyVirgilSignature {
		pub, err := verifier.GetPublicKeyFromBase64(verifier.virgilPublicKeySource)
		if err != nil {
			panic("NewVirgilCardVerifier: card crypto should support ed25519 because Virgil Cards service use this asymmetric key")
		}
		verifier.virgilPublicKey = pub
	}

	return verifier
}

func (v *VirgilCardVerifier) VerifyCard(card *Card) error {
	if card.PublicKey == nil {
		return ErrCardPublicKeyUnset
	}

	if v.verifySelfSignature {
		if err := v.ValidateSignerSignature(card, SelfSigner, card.PublicKey); err != nil {
			return errors.NewSDKError(err, "action", "VirgilCardVerifier.VerifyCard", "validate", "self")
		}
	}

	if v.verifyVirgilSignature {
		if err := v.ValidateSignerSignature(card, VirgilSigner, v.virgilPublicKey); err != nil {
			return errors.NewSDKError(err, "action", "VirgilCardVerifier.VerifyCard", "validate", "virgil")
		}
	}
	return v.verifyCardByWhitelist(card)
}

func (v *VirgilCardVerifier) verifyCardByWhitelist(card *Card) error {
	for _, whitelist := range v.whitelists {
		signatureVerified := false
		var err error
		for i := range whitelist.VerifierCredentials {
			var cred = whitelist.VerifierCredentials[i]
			if err = v.ValidateSignerSignature(card, cred.Signer, cred.PublicKey); err != nil {
				continue
			}

			signatureVerified = true
			break
		}
		if !signatureVerified {
			return err
		}
	}

	return nil
}

func (v *VirgilCardVerifier) GetPublicKeyFromBase64(str string) (crypto.PublicKey, error) {
	return v.crypto.ImportPublicKey([]byte(str))
}

func (v *VirgilCardVerifier) ValidateSignerSignature(card *Card, signer string, publicKey crypto.PublicKey) error {
	for _, s := range card.Signatures {
		if s.Signer == signer {
			snapshot := append(card.ContentSnapshot, s.Snapshot...)
			err := v.crypto.VerifySignature(snapshot, s.Signature, publicKey)

			return errors.NewSDKError(err,
				"action", "VirgilCardVerifier.ValidateSignerSignature",
				"validate", "signer",
				"signer", signer,
			)
		}
	}
	return ErrSignerWasNotFound
}

type Whitelist struct {
	VerifierCredentials []*VerifierCredentials
}

func NewWhitelist(credentials ...*VerifierCredentials) Whitelist {
	return Whitelist{
		VerifierCredentials: credentials,
	}
}

type VerifierCredentials struct {
	Signer    string
	PublicKey crypto.PublicKey
}
