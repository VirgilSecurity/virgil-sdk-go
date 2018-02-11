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
	"encoding/json"

	"github.com/pkg/errors"
	"gopkg.in/virgil.v5/cryptoapi"
)

type CSRParams struct {
	Identity   string
	PublicKey  cryptoapi.PublicKey
	PrivateKey cryptoapi.PrivateKey

	PreviousCardID string

	ExtraFields map[string]string
}
type CSRSignParams struct {
	Signer           string
	SignerPrivateKey cryptoapi.PrivateKey
	ExtraFields      map[string]string
}

type CSR struct {
	ID             string
	Identity       string
	PublicKeyBytes []byte
	Version        string
	CreatedAt      int64
	Snapshot       []byte
	Signatures     []*RawCardSignature
}

func sliceIndex(n int, predicate func(i int) bool) int {
	for i := 0; i < n; i++ {
		if predicate(i) {
			return i
		}
	}
	return -1
}

func (csr *CSR) Sign(crypto cryptoapi.CardCrypto, param *CSRSignParams) error {
	if param.SignerPrivateKey == nil || param.Signer == "" {
		return CSRSignParamIncorrectErr
	}

	var extraSnapshot []byte
	var err error
	signingSnapshot := csr.Snapshot
	if len(param.ExtraFields) != 0 {
		extraSnapshot, err = json.Marshal(param.ExtraFields)
		if err != nil {
			return errors.Wrap(err, "CSR.Sign: marshaling extra fields")
		}
		signingSnapshot = append(signingSnapshot, extraSnapshot...)
	}

	sign, err := crypto.GenerateSignature(signingSnapshot, param.SignerPrivateKey)
	if err != nil {
		return err
	}
	csr.Signatures = append(csr.Signatures, &RawCardSignature{
		ExtraFields: extraSnapshot,
		Signature:   sign,
		Signer:      param.Signer,
	})

	return nil
}
