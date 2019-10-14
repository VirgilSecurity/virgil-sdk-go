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

import "github.com/VirgilSecurity/virgil-sdk-go/crypto"

var KeyTypeMap = map[crypto.KeyType]interface{}{
	crypto.Default:         VirgilKeyPairType_FAST_EC_ED25519,
	crypto.RSA_2048:        VirgilKeyPairType_RSA_2048,
	crypto.RSA_3072:        VirgilKeyPairType_RSA_3072,
	crypto.RSA_4096:        VirgilKeyPairType_RSA_4096,
	crypto.RSA_8192:        VirgilKeyPairType_RSA_8192,
	crypto.EC_SECP256R1:    VirgilKeyPairType_EC_SECP256R1,
	crypto.EC_SECP384R1:    VirgilKeyPairType_EC_SECP384R1,
	crypto.EC_SECP521R1:    VirgilKeyPairType_EC_SECP521R1,
	crypto.EC_BP256R1:      VirgilKeyPairType_EC_BP256R1,
	crypto.EC_BP384R1:      VirgilKeyPairType_EC_BP384R1,
	crypto.EC_BP512R1:      VirgilKeyPairType_EC_BP512R1,
	crypto.EC_SECP256K1:    VirgilKeyPairType_EC_SECP256K1,
	crypto.EC_CURVE25519:   VirgilKeyPairType_EC_CURVE25519,
	crypto.FAST_EC_X25519:  VirgilKeyPairType_FAST_EC_X25519,
	crypto.FAST_EC_ED25519: VirgilKeyPairType_FAST_EC_ED25519,
}
