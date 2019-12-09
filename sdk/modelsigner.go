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
	"github.com/VirgilSecurity/virgil-sdk-go/crypto"
	"github.com/VirgilSecurity/virgil-sdk-go/crypto/cryptocgo"
	"github.com/VirgilSecurity/virgil-sdk-go/errors"
)

const (
	SelfSigner   = "self"
	VirgilSigner = "virgil"
)

var defaultCardCrypto crypto.CardCrypto = cryptocgo.NewVirgilCardCrypto()

type ModelSigner struct {
	Crypto crypto.CardCrypto
}

func (m *ModelSigner) Sign(model *RawSignedModel, signer string, privateKey crypto.PrivateKey, extraFields map[string]string) (err error) {
	var extraFieldsSnapshot []byte
	if extraFields != nil {
		extraFieldsSnapshot, err = TakeSnapshot(extraFields)
		if err != nil {
			return errors.NewSDKError(err, "action", "ModelSigner.Sign")
		}
	}

	err = m.signInternal(model, signParams{signerKey: privateKey, signer: signer}, extraFieldsSnapshot)
	return errors.NewSDKError(err, "action", "ModelSigner.Sign", "signer", signer)
}

func (m *ModelSigner) SignRaw(model *RawSignedModel, signer string, privateKey crypto.PrivateKey, extraFieldsSnapshot []byte) (err error) {
	err = m.signInternal(model, signParams{signerKey: privateKey, signer: signer}, extraFieldsSnapshot)
	return errors.NewSDKError(err, "action", "ModelSigner.SignRaw", "signer", signer)
}

func (m *ModelSigner) SelfSign(model *RawSignedModel, privateKey crypto.PrivateKey, extraFields map[string]string) (err error) {
	var extraFieldsSnapshot []byte
	if extraFields != nil {
		extraFieldsSnapshot, err = TakeSnapshot(extraFields)
		if err != nil {
			return errors.NewSDKError(err, "action", "ModelSigner.SelfSign")
		}
	}

	err = m.signInternal(model, signParams{signerKey: privateKey, signer: SelfSigner}, extraFieldsSnapshot)
	return errors.NewSDKError(err, "action", "ModelSigner.SelfSign")
}

func (m *ModelSigner) SelfSignRaw(model *RawSignedModel, privateKey crypto.PrivateKey, extraFieldsSnapshot []byte) (err error) {
	err = m.signInternal(model, signParams{signerKey: privateKey, signer: SelfSigner}, extraFieldsSnapshot)
	return errors.NewSDKError(err, "action", "ModelSigner.SelfSignRaw")
}

func (m *ModelSigner) signInternal(model *RawSignedModel, params signParams, extraFieldsSnapshot []byte) error {
	if model == nil {
		return ErrRawSignedModelIsMandatory
	}

	if err := m.CheckSignatureExists(model, params.signer); err != nil {
		return err
	}

	resultSnapshot := append(model.ContentSnapshot, extraFieldsSnapshot...)
	signature, err := m.getCrypto().GenerateSignature(resultSnapshot, params.signerKey)
	if err != nil {
		return err
	}

	model.Signatures = append(model.Signatures, &RawCardSignature{
		Signer:    params.signer,
		Snapshot:  extraFieldsSnapshot,
		Signature: signature,
	})
	return nil
}

func (m *ModelSigner) CheckSignatureExists(model *RawSignedModel, signer string) error {
	for _, s := range model.Signatures {
		if s.Signer == signer {
			return errors.NewSDKError(ErrDuplicateSigner, "action", "ModelSigner.CheckSignatureExists")
		}
	}
	return nil
}

func (m *ModelSigner) getCrypto() crypto.CardCrypto {
	if m.Crypto == nil {
		return defaultCardCrypto
	}
	return m.Crypto
}

type signParams struct {
	signerKey crypto.PrivateKey
	signer    string
}
