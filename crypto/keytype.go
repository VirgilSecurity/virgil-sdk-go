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

import (
	"github.com/VirgilSecurity/virgil-crypto-c/wrappers/go/foundation"
)

// KeyType describes the algorithm configuration for a keypair.
// Use the package-level vars for recommended types or the constructor
// functions HybridKEM and CompoundKey for custom combinations.
// KeyType is comparable with ==.
type KeyType struct {
	rsaBitlen uint      // nonzero for RSA; all other fields must be zero
	simple    Algorithm // single-algorithm key (Ed25519, Curve25519, P256r1)
	cipher    Algorithm // cipher component of a compound or standalone hybrid KEM
	pqCipher  Algorithm // post-quantum cipher component (AlgNone if not hybrid)
	signer    Algorithm // signer component of a compound key
	pqSigner  Algorithm // post-quantum signer component (AlgNone if not hybrid signer)
}

// Recommended named types — use these for new code.
var (
	DefaultKeyType = Ed25519

	// Classical
	P256r1     = KeyType{simple: AlgP256r1}
	Curve25519 = KeyType{simple: AlgCurve25519}
	Ed25519    = KeyType{simple: AlgEd25519}

	// Recommended compound types
	Curve25519Ed25519                = CompoundKey(AlgCurve25519, AlgNone, AlgEd25519, AlgNone)
	Curve25519MlKem768Ed25519Falcon  = CompoundKey(AlgCurve25519, AlgMlKem768, AlgEd25519, AlgFalcon)
	Curve25519MlKem768Ed25519MlDsa65 = CompoundKey(AlgCurve25519, AlgMlKem768, AlgEd25519, AlgMlDsa65)
)

// RsaKey returns a KeyType for an RSA keypair with the given bit length.
// Prefer elliptic-curve types for new integrations; RSA is provided for
// interoperability with legacy systems.
func RsaKey(bitlen uint) KeyType {
	return KeyType{rsaBitlen: bitlen}
}

// HybridKEM returns a KeyType for a hybrid key-encapsulation mechanism.
// classical is the classical cipher algorithm (e.g. AlgCurve25519) and
// postQuantum is the post-quantum counterpart (e.g. AlgMlKem768).
func HybridKEM(classical, postQuantum Algorithm) KeyType {
	return KeyType{cipher: classical, pqCipher: postQuantum}
}

// CompoundKey returns a KeyType for a compound key that combines a cipher
// part and a signer part, each optionally hybrid.
// Pass AlgNone for pqCipher or pqSigner to use a classical-only component.
func CompoundKey(cipher, pqCipher, signer, pqSigner Algorithm) KeyType {
	return KeyType{cipher: cipher, pqCipher: pqCipher, signer: signer, pqSigner: pqSigner}
}

func (kt KeyType) generatePrivateKey(kp *foundation.KeyProvider) (foundation.PrivateKey, error) {
	switch {
	case kt.rsaBitlen > 0:
		kp.SetRsaParams(kt.rsaBitlen)
		return kp.GeneratePrivateKey(foundation.AlgIdRsa)

	case kt.simple != AlgNone:
		return kp.GeneratePrivateKey(algToFoundation(kt.simple))

	case kt.cipher != AlgNone && kt.signer != AlgNone:
		return kp.GenerateCompoundHybridPrivateKey(
			algToFoundation(kt.cipher),
			algToFoundation(kt.pqCipher),
			algToFoundation(kt.signer),
			algToFoundation(kt.pqSigner),
		)

	case kt.cipher != AlgNone && kt.pqCipher != AlgNone:
		return kp.GenerateHybridPrivateKey(
			algToFoundation(kt.cipher),
			algToFoundation(kt.pqCipher),
		)

	default:
		return nil, ErrUnsupportedKeyType
	}
}

func getKeyType(obj deleter) (KeyType, error) {
	key, ok := obj.(foundation.Key)
	if !ok {
		return DefaultKeyType, ErrUnsupportedKeyType
	}

	algInfo, err := key.AlgInfo()
	if err != nil {
		return DefaultKeyType, err
	}

	info := foundation.NewKeyInfoWithAlgInfo(algInfo)
	defer info.Delete()

	if info.IsCompound() {
		var cipher, pqCipher, signer, pqSigner Algorithm
		if info.IsCompoundHybridCipher() {
			cipher = algFromFoundation(info.CompoundHybridCipherFirstKeyAlgId())
			pqCipher = algFromFoundation(info.CompoundHybridCipherSecondKeyAlgId())
		} else {
			cipher = algFromFoundation(info.CompoundCipherAlgId())
		}
		if info.IsCompoundHybridSigner() {
			signer = algFromFoundation(info.CompoundHybridSignerFirstKeyAlgId())
			pqSigner = algFromFoundation(info.CompoundHybridSignerSecondKeyAlgId())
		} else {
			signer = algFromFoundation(info.CompoundSignerAlgId())
		}
		return KeyType{cipher: cipher, pqCipher: pqCipher, signer: signer, pqSigner: pqSigner}, nil
	}

	if info.IsHybrid() {
		return KeyType{
			cipher:   algFromFoundation(info.HybridFirstKeyAlgId()),
			pqCipher: algFromFoundation(info.HybridSecondKeyAlgId()),
		}, nil
	}

	if algInfo.AlgId() == foundation.AlgIdRsa {
		return KeyType{rsaBitlen: key.Bitlen()}, nil
	}

	alg := algFromFoundation(algInfo.AlgId())
	if alg == AlgNone {
		return DefaultKeyType, ErrUnsupportedKeyType
	}
	return KeyType{simple: alg}, nil
}
