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
	"encoding/base64"
	"encoding/json"
	"time"
)

const (
	CardVersion = "5.0"
)

func GenerateRawCard(crypto Crypto, cardParams CardParams, createdAt time.Time) (*RawSignedModel, error) {
	if crypto == nil {
		return nil, ErrCryptoIsMandatory
	}

	if err := cardParams.Validate(); err != nil {
		return nil, err
	}
	publicKey, err := crypto.ExportPublicKey(cardParams.PrivateKey.PublicKey())
	if err != nil {
		return nil, err
	}
	snapshot, err := TakeSnapshot(RawCardContent{
		Identity:       cardParams.Identity,
		PublicKey:      publicKey,
		CreatedAt:      createdAt.UTC().Unix(),
		PreviousCardId: cardParams.PreviousCardId,
		Version:        CardVersion,
	})
	if err != nil {
		return nil, err
	}

	return &RawSignedModel{
		ContentSnapshot: snapshot,
	}, nil
}

func GenerateRawSignedModelFromString(str string) (*RawSignedModel, error) {
	data, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return nil, err
	}
	return GenerateRawSignedModelFromJson(string(data))
}

func GenerateRawSignedModelFromJson(json string) (*RawSignedModel, error) {
	var model *RawSignedModel
	err := ParseSnapshot([]byte(json), &model)
	return model, err
}

func ParseCard(crypto Crypto, card *Card) (*RawSignedModel, error) {
	if crypto == nil {
		return nil, ErrCryptoIsMandatory
	}
	if card == nil {
		return nil, ErrCardIsMandatory
	}

	signatures := make([]*RawCardSignature, len(card.Signatures))
	for i, s := range card.Signatures {
		signatures[i] = &RawCardSignature{
			Signer:    s.Signer,
			Signature: s.Signature,
			Snapshot:  s.Snapshot,
		}
	}

	return &RawSignedModel{
		ContentSnapshot: card.ContentSnapshot,
		Signatures:      signatures,
	}, nil
}

type RawCardContent struct {
	Identity       string `json:"identity"`
	PublicKey      []byte `json:"public_key"`
	Version        string `json:"version"`
	CreatedAt      int64  `json:"created_at"`
	PreviousCardId string `json:"previous_card_id,omitempty"`
}

type RawCardSignature struct {
	Signer    string `json:"signer,omitempty"`
	Signature []byte `json:"signature,omitempty"`
	Snapshot  []byte `json:"snapshot,omitempty"`
}

type RawSignedModel struct {
	ContentSnapshot []byte              `json:"content_snapshot"`
	Signatures      []*RawCardSignature `json:"signatures,omitempty"`
}

func (r *RawSignedModel) ExportAsBase64EncodedString() (string, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(raw), nil
}

func (r *RawSignedModel) ExportAsJson() (string, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return "", err
	}

	return string(raw), nil
}
