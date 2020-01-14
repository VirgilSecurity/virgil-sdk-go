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

package crypto

import (
	"github.com/VirgilSecurity/virgil-sdk-go/v6/crypto/internal/foundation"
)

type KeyType int

// nolint: golint
const (
	DefaultKeyType KeyType = iota
	RSA_2048
	RSA_3072
	RSA_4096
	RSA_8192
	EC_SECP256R1
	EC_SECP384R1
	EC_SECP521R1
	EC_BP256R1
	EC_BP384R1
	EC_BP512R1
	EC_SECP256K1
	EC_CURVE25519
	FAST_EC_X25519
	FAST_EC_ED25519
	CURVE25519_ED25519
	CURVE25519Round5_ED25519Falcon
)

type keyGen interface {
	GeneratePrivateKey(kp *foundation.KeyProvider) (foundation.PrivateKey, error)
}

var keyTypeMap = map[KeyType]keyGen{
	DefaultKeyType:  keyType(foundation.AlgIdEd25519),
	RSA_2048:        rsaKeyType(2048),
	RSA_3072:        rsaKeyType(3072),
	RSA_4096:        rsaKeyType(4096),
	RSA_8192:        rsaKeyType(8192),
	EC_SECP256R1:    keyType(foundation.AlgIdSecp256r1),
	EC_CURVE25519:   keyType(foundation.AlgIdCurve25519),
	FAST_EC_ED25519: keyType(foundation.AlgIdEd25519),
	CURVE25519_ED25519: &compoundHybridKeyType{
		cipherFirstKeyAlgId:  foundation.AlgIdCurve25519,
		cipherSecondKeyAlgId: foundation.AlgIdNone,
		signerFirstKeyAlgId:  foundation.AlgIdEd25519,
		signerSecondKeyAlgId: foundation.AlgIdNone,
	},
	CURVE25519Round5_ED25519Falcon: &compoundHybridKeyType{
		cipherFirstKeyAlgId:  foundation.AlgIdCurve25519,
		cipherSecondKeyAlgId: foundation.AlgIdRound5Nd5kem5d,
		signerFirstKeyAlgId:  foundation.AlgIdEd25519,
		signerSecondKeyAlgId: foundation.AlgIdFalcon,
	},
}

type keyType foundation.AlgId

func (t keyType) GeneratePrivateKey(kp *foundation.KeyProvider) (foundation.PrivateKey, error) {
	return kp.GeneratePrivateKey(foundation.AlgId(t))
}

type rsaKeyType int

func (t rsaKeyType) GeneratePrivateKey(kp *foundation.KeyProvider) (foundation.PrivateKey, error) {
	kp.SetRsaParams(uint(t))
	return kp.GeneratePrivateKey(foundation.AlgIdRsa)
}

type compoundHybridKeyType struct {
	cipherFirstKeyAlgId  foundation.AlgId
	cipherSecondKeyAlgId foundation.AlgId
	signerFirstKeyAlgId  foundation.AlgId
	signerSecondKeyAlgId foundation.AlgId
}

func (t *compoundHybridKeyType) GeneratePrivateKey(kp *foundation.KeyProvider) (foundation.PrivateKey, error) {
	return kp.GenerateCompoundHybridPrivateKey(
		t.cipherFirstKeyAlgId,
		t.cipherSecondKeyAlgId,
		t.signerFirstKeyAlgId,
		t.signerSecondKeyAlgId,
	)
}
