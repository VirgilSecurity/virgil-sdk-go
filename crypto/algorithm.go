/*
 * Copyright (C) 2015-2026 Virgil Security Inc.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
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
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */

package crypto

import "github.com/VirgilSecurity/virgil-crypto-c/wrappers/go/foundation"

// Algorithm identifies a single cryptographic primitive.
type Algorithm int

const (
	AlgNone      Algorithm = iota
	AlgEd25519             // classical signature
	AlgCurve25519          // classical KEM / ECDH
	AlgP256r1              // classical NIST P-256
	AlgFalcon              // post-quantum signature (NIST alternate)
	AlgMlKem768            // post-quantum KEM   (NIST FIPS 203)
	AlgMlDsa65             // post-quantum signature (NIST FIPS 204)
)

func algToFoundation(a Algorithm) foundation.AlgId {
	switch a {
	case AlgEd25519:
		return foundation.AlgIdEd25519
	case AlgCurve25519:
		return foundation.AlgIdCurve25519
	case AlgP256r1:
		return foundation.AlgIdSecp256r1
	case AlgFalcon:
		return foundation.AlgIdFalcon
	case AlgMlKem768:
		return foundation.AlgIdMlKem768
	case AlgMlDsa65:
		return foundation.AlgIdMlDsa65
	default:
		return foundation.AlgIdNone
	}
}

func algFromFoundation(id foundation.AlgId) Algorithm {
	switch id {
	case foundation.AlgIdEd25519:
		return AlgEd25519
	case foundation.AlgIdCurve25519:
		return AlgCurve25519
	case foundation.AlgIdSecp256r1:
		return AlgP256r1
	case foundation.AlgIdFalcon:
		return AlgFalcon
	case foundation.AlgIdMlKem768:
		return AlgMlKem768
	case foundation.AlgIdMlDsa65:
		return AlgMlDsa65
	default:
		return AlgNone
	}
}
