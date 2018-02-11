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

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/pkg/errors"

	"gopkg.in/virgil.v5/common"
	"gopkg.in/virgil.v5/cryptoapi"
)

type Validator interface {
	Validate(crypto cryptoapi.CardCrypto, card *Card) error
}

type HttpClient common.HttpClient

const (
	SignerTypeSelf        = "self"
	SignerTypeApplication = "app"
	SignerTypeVirgil      = "virgil"
	SignerTypeExtra       = "extra"
)

type CardsManager struct {
	Crypto     cryptoapi.CardCrypto
	Validator  Validator
	ApiUrl     string
	HttpClient HttpClient
}

func (cm *CardsManager) GetCard(id string) (*Card, error) {
	var rawCard *RawCard
	err := cm.send(http.MethodGet, "/card/v5/"+id, nil, &rawCard)
	if err != nil {
		return nil, err
	}
	card, err := cm.raw2Card(rawCard)
	if err != nil {
		return nil, err
	}

	err = cm.validate([]*Card{card})
	return card, err
}

func (cm *CardsManager) SearchCards(identity string) ([]*Card, error) {
	var rawCards []*RawCard
	err := cm.send(http.MethodPost, "/card/v5/actions/search", map[string]string{"identity": identity}, &rawCards)
	if err != nil {
		return nil, err
	}

	cards := make([]*Card, len(rawCards))
	for i, rc := range rawCards {
		cards[i], err = cm.raw2Card(rc)
		if err != nil {
			return nil, err
		}
	}

	err = cm.validate(cards)
	return cards, err
}

func (cm *CardsManager) PublishCard(scr *CSR) (*Card, error) {
	var rawCard *RawCard
	err := cm.send(http.MethodPost, "/card/v5", &RawCard{Signatures: scr.Signatures, Snapshot: scr.Snapshot}, &rawCard)
	if err != nil {
		return nil, err
	}
	card, err := cm.raw2Card(rawCard)
	if err != nil {
		return nil, err
	}

	err = cm.validate([]*Card{card})
	return card, err
}

func (cm *CardsManager) GenerateCSR(param *CSRParams) (*CSR, error) {
	if param.PublicKey == nil {
		return nil, CSRPublicKeyEmptyErr
	}
	if param.Identity == "" {
		return nil, CSRIdentityEmptyErr
	}
	exportedPubKey, err := cm.getCrypto().ExportPublicKey(param.PublicKey)
	if err != nil {
		return nil, err
	}

	t := time.Now().UTC().Unix()
	cardInfo := &RawCardSnapshot{
		Identity:       param.Identity,
		PublicKeyBytes: exportedPubKey,
		PreviousCardID: param.PreviousCardID,
		Version:        "5.0",
		CreatedAt:      t,
	}
	snapshot, err := json.Marshal(cardInfo)
	if err != nil {
		return nil, errors.Wrap(err, "CardsManager: marshaling card's info")
	}
	csr := &CSR{
		ID:             hex.EncodeToString(cm.getCrypto().GenerateSHA512(snapshot)[:32]),
		CreatedAt:      cardInfo.CreatedAt,
		Identity:       cardInfo.Identity,
		PublicKeyBytes: cardInfo.PublicKeyBytes,
		Version:        cardInfo.Version,
		Snapshot:       snapshot,
	}
	if param.PrivateKey != nil {
		err := csr.Sign(cm.getCrypto(), &CSRSignParams{
			ExtraFields:      param.ExtraFields,
			Signer:           SignerTypeSelf,
			SignerPrivateKey: param.PrivateKey,
		})
		if err != nil {
			return csr, err
		}
	}
	return csr, nil
}

func (cm *CardsManager) SignCSR(csr *CSR, params *CSRSignParams) error {
	return csr.Sign(cm.getCrypto(), params)
}

func (cm *CardsManager) ImportCSR(source []byte) (CSR, error) {
	var csr CSR
	var raw RawCard
	err := json.Unmarshal(source, &raw)
	if err != nil {
		return csr, errors.Wrap(err, "CardsMangerImportCSR.: unmarshal source")
	}
	var info *RawCardSnapshot
	err = json.Unmarshal(raw.Snapshot, &info)
	if err != nil {
		return csr, errors.Wrap(err, "CardsMangerImportCSR.: unmarshal csr snapshot info")
	}
	csr = CSR{
		Identity:       info.Identity,
		PublicKeyBytes: info.PublicKeyBytes,
		Snapshot:       raw.Snapshot,
		Version:        info.Version,
		CreatedAt:      info.CreatedAt,
		Signatures:     raw.Signatures,
	}

	sn := raw.Snapshot
	index := sliceIndex(len(csr.Signatures), func(i int) bool {
		return csr.Signatures[i].Signer == string(SignerTypeSelf)
	})
	if index != -1 && len(csr.Signatures[index].ExtraFields) != 0 {
		sn = append(sn, csr.Signatures[index].ExtraFields...)
	}
	csr.ID = hex.EncodeToString(cm.getCrypto().GenerateSHA512(sn)[:32])

	return csr, nil
}

func (cm *CardsManager) validate(cards []*Card) error {
	if cm.Validator == nil {
		return nil
	}
	for _, card := range cards {
		err := cm.Validator.Validate(cm.getCrypto(), card)
		if err != nil {
			return err
		}
	}
	return nil
}

func (cm *CardsManager) raw2Card(raw *RawCard) (card *Card, err error) {
	var cardInfo *RawCardSnapshot

	err = json.Unmarshal(raw.Snapshot, &cardInfo)
	if err != nil {
		return nil, errors.Wrap(err, "CardsManager: cannot unmarshal card snapshot")
	}
	pubKey, err := cm.getCrypto().ImportPublicKey(cardInfo.PublicKeyBytes)
	if err != nil {
		return nil, err
	}
	card = &Card{
		PublicKey: pubKey,
		Identity:  cardInfo.Identity,
		Snapshot:  raw.Snapshot,
	}

	if cardInfo.Version == "5.0" {
		card.CreatedAt = time.Unix(cardInfo.CreatedAt, 0)
		card.Version = cardInfo.Version
		card.Signature = make([]*CardSignature, len(raw.Signatures))
		for i, rs := range raw.Signatures {
			cs := &CardSignature{
				Signer:    rs.Signer,
				Signature: rs.Signature,
				Snapshot:  []byte{},
			}
			if rs.ExtraFields != nil {
				var exf map[string]string
				err = json.Unmarshal(rs.ExtraFields, &exf)
				if err != nil {
					return card, errors.Wrap(err, "CardsManager: unmarshal extra fields of signature")
				}
				cs.ExtraFields = exf
				cs.Snapshot = rs.ExtraFields
			}

			card.Signature[i] = cs
			if card.Signature[i].Signer == SignerTypeSelf {
				fpData := append(raw.Snapshot, rs.ExtraFields...)
				fp := cm.getCrypto().GenerateSHA512(fpData)[:32]
				card.ID = hex.EncodeToString(fp)
			}
		}

	} else { // try convert from 4.0 to 5.0
		card.Version = raw.Meta.Version
		t, err := time.Parse("2006-01-02T15:04:05-0700", raw.Meta.CreatedAt)
		if err != nil {
			return card, errors.Wrap(err, "CardsManager: error parse of time of create card of v4 format")
		}
		card.CreatedAt = t

		fp := cm.getCrypto().GenerateSHA512(raw.Snapshot)
		card.ID = hex.EncodeToString(fp)

		card.Signature = make([]*CardSignature, len(raw.Meta.Signatures))
		var i = 0
		for signerID, sign := range raw.Meta.Signatures {
			card.Signature[i] = &CardSignature{
				Signature: sign,
				Signer:    signerID,
				Snapshot:  []byte{},
			}
		}
	}

	return
}

func (cm *CardsManager) send(method string, url string, payload interface{}, respObj interface{}) error {
	client := cm.getVirgilClient()
	err := client.Send(method, url, payload, respObj)
	if err != nil {
		if apiErr, ok := err.(common.VirgilAPIError); ok {
			return CardsAPIError(apiErr)
		}
		return err
	}
	return nil
}

func (cm *CardsManager) getCrypto() cryptoapi.CardCrypto {
	if cm.Crypto != nil {
		return cm.Crypto
	}
	return DefaultCrypto
}

func (cm *CardsManager) getUrl() string {
	if cm.ApiUrl != "" {
		return cm.ApiUrl
	}
	return "https://api.virgilsecurity.com"
}

func (cm *CardsManager) getHttpClient() HttpClient {
	if cm.HttpClient != nil {
		return cm.HttpClient
	}
	return http.DefaultClient
}

func (cm *CardsManager) getVirgilClient() common.VirgilHttpClient {
	return common.VirgilHttpClient{
		Address: cm.getUrl(),
		Client:  cm.getHttpClient(),
	}
}
