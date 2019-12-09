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
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"

	"time"

	"github.com/VirgilSecurity/virgil-sdk-go/crypto"
)

func ParseRawCard(crypto crypto.CardCrypto, model *RawSignedModel, isOutdated bool) (*Card, error) {
	if crypto == nil {
		return nil, ErrCryptoIsMandatory
	}
	if model == nil {
		return nil, ErrRawSignedModelIsMandatory
	}

	var content RawCardContent
	err := ParseSnapshot(model.ContentSnapshot, &content)
	if err != nil {
		return nil, err
	}

	signatures := make([]*CardSignature, len(model.Signatures))
	for i, signature := range model.Signatures {
		var extraFields map[string]string
		if len(signature.Snapshot) > 0 {
			if nil != ParseSnapshot(signature.Snapshot, &extraFields) {
				extraFields = nil
			}
		}
		signatures[i] = &CardSignature{
			Snapshot:    signature.Snapshot,
			Signer:      signature.Signer,
			Signature:   signature.Signature,
			ExtraFields: extraFields,
		}
	}

	publicKey, err := crypto.ImportPublicKey(content.PublicKey)
	if err != nil {
		return nil, err
	}

	return &Card{
		Id:              GenerateCardID(model.ContentSnapshot),
		ContentSnapshot: model.ContentSnapshot,
		Signatures:      signatures,
		Version:         content.Version,
		PreviousCardId:  content.PreviousCardId,
		CreatedAt:       time.Unix(content.CreatedAt, 0),
		Identity:        content.Identity,
		IsOutdated:      isOutdated,
		PublicKey:       publicKey,
	}, nil
}

func GenerateCardID(data []byte) string {
	h := sha512.Sum512(data)
	return hex.EncodeToString(h[:32])
}

func ParseRawCards(crypto crypto.CardCrypto, models ...*RawSignedModel) ([]*Card, error) {
	cards := make([]*Card, len(models))
	for i, model := range models {
		card, err := ParseRawCard(crypto, model, false)
		if err != nil {
			return nil, err
		}
		cards[i] = card
	}
	return cards, nil
}

func LinkCards(cards ...*Card) []*Card {
	unsortedCards := make(map[string]*Card)

	for _, card := range cards {
		unsortedCards[card.Id] = card
	}

	for _, card := range cards {
		if card.PreviousCardId != "" {
			prev, ok := unsortedCards[card.PreviousCardId]
			if ok {
				card.PreviousCard = prev
				prev.IsOutdated = true
				delete(unsortedCards, card.PreviousCardId)
			}
		}
	}

	result := make([]*Card, 0, len(unsortedCards))
	for _, card := range unsortedCards {
		result = append(result, card)
	}
	return result
}

func TakeSnapshot(obj interface{}) ([]byte, error) {
	return json.Marshal(obj)
}

func ParseSnapshot(data []byte, obj interface{}) error {
	decoder := json.NewDecoder(bytes.NewBuffer(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(obj)
}
