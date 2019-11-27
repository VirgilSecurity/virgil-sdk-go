/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2015-2018, Virgil Security, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 *  Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package cryptocgo

import (
	"github.com/VirgilSecurity/virgil-sdk-go/crypto"
	"github.com/VirgilSecurity/virgil-sdk-go/crypto/cryptocgo/internal/foundation"
)

var keyTypeMap = map[crypto.KeyType]keyAlg{
	crypto.Default:         keyType(foundation.AlgIdEd25519),
	crypto.RSA_2048:        rsaKeyType{foundation.AlgIdRsa, 2048},
	crypto.RSA_3072:        rsaKeyType{foundation.AlgIdRsa, 3072},
	crypto.RSA_4096:        rsaKeyType{foundation.AlgIdRsa, 4096},
	crypto.RSA_8192:        rsaKeyType{foundation.AlgIdRsa, 8192},
	crypto.EC_SECP256R1:    keyType(foundation.AlgIdSecp256r1),
	crypto.EC_CURVE25519:   keyType(foundation.AlgIdCurve25519),
	crypto.FAST_EC_ED25519: keyType(foundation.AlgIdEd25519),
	//  crypto.EC_SECP384R1:    foundation.algID_SEC VirgilKeyPairType_EC_SECP384R1,
	//  crypto.EC_SECP521R1:    foundation.ALg_ID_512 VirgilKeyPairType_EC_SECP521R1,
	//  crypto.EC_BP256R1:      foundation.alg_idb VirgilKeyPairType_EC_BP256R1,
	//  crypto.EC_BP384R1:      VirgilKeyPairType_EC_BP384R1,
	//  crypto.EC_BP512R1:      VirgilKeyPairType_EC_BP512R1,
	//  crypto.EC_SECP256K1:    foundation.secp VirgilKeyPairType_EC_SECP256K1,
	//  crypto.FAST_EC_X25519:  VirgilKeyPairType_FAST_EC_X25519,
}

type keyAlg interface {
	AlgID() foundation.AlgId
}

type keyType foundation.AlgId

func (t keyType) AlgID() foundation.AlgId {
	return foundation.AlgId(t)
}

type rsaKeyAlg interface {
	keyAlg
	Len() uint32
}

type rsaKeyType struct {
	t   foundation.AlgId
	len uint32
}

func (t rsaKeyType) AlgID() foundation.AlgId {
	return t.t
}
func (t rsaKeyType) Len() uint32 {
	return t.len
}
