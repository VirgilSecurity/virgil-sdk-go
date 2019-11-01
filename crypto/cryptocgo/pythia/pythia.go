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

package pythia

// #include "virgil/crypto/pythia/virgil_pythia_c.h"
import "C"

import (
	"fmt"

	"github.com/VirgilSecurity/virgil-sdk-go/crypto"
	"github.com/VirgilSecurity/virgil-sdk-go/crypto/cryptocgo"
)

//nolint: golint
var (
	BN_SIZE = int(C.PYTHIA_BN_BUF_SIZE)
	G1_SIZE = int(C.PYTHIA_G1_BUF_SIZE)
	G2_SIZE = int(C.PYTHIA_G2_BUF_SIZE)
	GT_SIZE = int(C.PYTHIA_GT_BUF_SIZE)
)

type Pythia struct {
}

func New() *Pythia {
	return &Pythia{}
}

// Blind turns password into a pseudo-random string.
func (p *Pythia) Blind(password []byte) (blindedPassword, blindingSecret []byte, err error) {
	defer deferRecover(&err)

	blindedPasswordBuf := NewBuf(G1_SIZE)
	blindingSecretBuf := NewBuf(BN_SIZE)
	passwordBuf := NewBufWithData(password)

	defer deferClose(blindedPasswordBuf, blindingSecretBuf, passwordBuf)

	pErr := C.virgil_pythia_blind(passwordBuf.inBuf, blindedPasswordBuf.inBuf, blindingSecretBuf.inBuf)
	if pErr != 0 {
		err = NewPythiaError(int(pErr), "Internal Pythia error")
		return
	}

	return blindedPasswordBuf.GetData(), blindingSecretBuf.GetData(), nil
}

// Deblind unmasks value y with previously returned secret from Blind()
func (p *Pythia) Deblind(transformedPassword []byte, blindingSecret []byte) (deblindedPassword []byte, err error) {

	defer deferRecover(&err)

	transformedPasswordBuf := NewBufWithData(transformedPassword)
	secretBuf := NewBufWithData(blindingSecret)
	deblindedBuf := NewBuf(GT_SIZE)

	defer deferClose(transformedPasswordBuf, secretBuf, deblindedBuf)

	pErr := C.virgil_pythia_deblind(transformedPasswordBuf.inBuf, secretBuf.inBuf, deblindedBuf.inBuf)
	if pErr != 0 {
		err = NewPythiaError(int(pErr), "Internal Pythia error")
		return
	}

	return deblindedBuf.GetData(), nil
}

// ComputeTransformationKeypair Computes transformation private and public key.
//
// @param [in] transformation_key_id - ensemble key ID used to enclose operations in subsets.
// @param [in] pythia_secret - global common for all secret random Key.
// @param [in] pythia_scope_secret - ensemble secret generated and versioned transparently.
// @param [out] transformation_private_key - BN transformation_private_key Pythia's private key
//              which was generated using pythia_secret and pythia_scope_secret.
//              This key is used to emit proof tokens (proof_value_c, proof_value_u).
// @param [out] transformation_public_key
//
// @return 0 if succeeded, -1 otherwise
func (p *Pythia) ComputeTransformationKeypair(
	transformationKeyID []byte,
	pythiaSecret []byte,
	pythiaScopeSecret []byte,
) (privateKey, publicKey []byte, err error) {

	defer deferRecover(&err)

	transformationKeyIDBuf := NewBufWithData(transformationKeyID)
	pythiaSecretBuf := NewBufWithData(pythiaSecret)
	pythiaScopeSecretBuf := NewBufWithData(pythiaScopeSecret)
	privateKeyBuf := NewBuf(G2_SIZE)
	publicKeyBuf := NewBuf(G2_SIZE)

	defer deferClose(transformationKeyIDBuf, pythiaSecretBuf, pythiaScopeSecretBuf, privateKeyBuf, publicKeyBuf)

	pErr := C.virgil_pythia_compute_transformation_key_pair(
		transformationKeyIDBuf.inBuf,
		pythiaSecretBuf.inBuf,
		pythiaScopeSecretBuf.inBuf,
		privateKeyBuf.inBuf,
		publicKeyBuf.inBuf,
	)
	if pErr != 0 {
		err = NewPythiaError(int(pErr), "Internal Pythia error")
		return
	}

	return privateKeyBuf.GetData(), publicKeyBuf.GetData(), nil
}

// Transform turns blinded password into cryptographically strong value.
/**
 * @brief Transforms blinded password using the private key, generated from pythia_secret + pythia_scope_secret.
 *
 * @param [in] blinded_password - G1 password obfuscated into a pseudo-random string.
 * @param [in] tweak - some random value used to transform a password.
 * @param [in] transformation_private_key - BN transformation private key.
 * @param [out] transformed_password - GT blinded password, protected using server secret
 *              (transformation private key + tweak).
 * @param [out] transformed_tweak - G2 tweak value turned into an elliptic curve point.
 *              This value is used by Prove() operation.
 *
 * @return 0 if succeeded, -1 otherwise
 */
func (p *Pythia) Transform(
	blindedPassword,
	tweak,
	transformationPrivateKey []byte,
) (transformedPassword, transformedTweak []byte, err error) {

	defer deferRecover(&err)

	tweakBuf := NewBufWithData(tweak)
	blindedPasswordBuf := NewBufWithData(blindedPassword)
	transformationPrivateKeyBuf := NewBufWithData(transformationPrivateKey)

	transformedPasswordBuf := NewBuf(GT_SIZE)
	transformedTweakBuf := NewBuf(G2_SIZE)

	defer deferClose(tweakBuf, blindedPasswordBuf, transformationPrivateKeyBuf, transformedPasswordBuf, transformedTweakBuf)

	pErr := C.virgil_pythia_transform(
		blindedPasswordBuf.inBuf,
		tweakBuf.inBuf,
		transformationPrivateKeyBuf.inBuf,
		transformedPasswordBuf.inBuf,
		transformedTweakBuf.inBuf,
	)
	if pErr != 0 {
		err = NewPythiaError(int(pErr), "Internal Pythia error")
		return
	}

	return transformedPasswordBuf.GetData(), transformedTweakBuf.GetData(), nil
}

// Prove proves that server possesses secret values that are used to protect password
func (p *Pythia) Prove(
	transformedPassword []byte,
	blindedPassword []byte,
	transformedTweak []byte,
	transformationPrivateKey []byte,
	transformationPublicKey []byte,
) (proofValueC []byte, proofValueU []byte, err error) {

	defer deferRecover(&err)

	blindedPasswordBuf := NewBufWithData(blindedPassword)
	transformedTweakBuf := NewBufWithData(transformedTweak)
	transformationPrivateKeyBuf := NewBufWithData(transformationPrivateKey)
	transformedPasswordBuf := NewBufWithData(transformedPassword)
	transformationPublicKeyBuf := NewBufWithData(transformationPublicKey)
	proofValueCBuf := NewBuf(BN_SIZE)
	proofValueUBuf := NewBuf(BN_SIZE)

	defer deferClose(blindedPasswordBuf, transformedTweakBuf, transformationPrivateKeyBuf, transformedPasswordBuf,
		transformationPublicKeyBuf, proofValueCBuf, proofValueUBuf)

	pErr := C.virgil_pythia_prove(
		transformedPasswordBuf.inBuf,
		blindedPasswordBuf.inBuf,
		transformedTweakBuf.inBuf,
		transformationPrivateKeyBuf.inBuf,
		transformationPublicKeyBuf.inBuf,
		proofValueCBuf.inBuf,
		proofValueUBuf.inBuf,
	)
	if pErr != 0 {
		return nil, nil, NewPythiaError(int(pErr), "Internal Pythia error")
	}

	return proofValueCBuf.GetData(), proofValueUBuf.GetData(), nil
}

//Verify The protocol enables a client to verify that
//the output of Transform() is correct, assuming the client has
//previously stored p. The server accompanies the output
//y of the Transform() with a zero-knowledge proof (c, u) of correctness
func (p *Pythia) Verify(transformedPassword, blindedPassword, tweak, transformationPublicKey, proofValueC, proofValueU []byte) (err error) {

	defer deferRecover(&err)

	blindedPasswordBuf := NewBufWithData(blindedPassword)
	tweakBuf := NewBufWithData(tweak)
	transformedPasswordBuf := NewBufWithData(transformedPassword)
	transformationPublicKeyBuf := NewBufWithData(transformationPublicKey)
	proofValueCBuf := NewBufWithData(proofValueC)
	proofValueUBuf := NewBufWithData(proofValueU)

	defer deferClose(blindedPasswordBuf, tweakBuf, transformedPasswordBuf, transformationPublicKeyBuf, proofValueCBuf, proofValueUBuf)

	var verified C.int

	pErr := C.virgil_pythia_verify(
		transformedPasswordBuf.inBuf,
		blindedPasswordBuf.inBuf,
		tweakBuf.inBuf,
		transformationPublicKeyBuf.inBuf,
		proofValueCBuf.inBuf,
		proofValueUBuf.inBuf,
		&verified,
	)
	if pErr != 0 {
		err = NewPythiaError(int(pErr), "Internal Pythia error")
		return
	}

	if int(verified) != 1 {
		return NewPythiaError(int(pErr), "Verification failed")
	}

	return nil
}

// GetPasswordUpdateToken generates token that can update protected passwords
// from the combination of (old) w1, msk1, ssk1 to (new) w2, msk2, ssk2
func (p *Pythia) GetPasswordUpdateToken(
	previousTransformationPrivateKey,
	newTransformationPrivateKey []byte,
) (passwordUpdateToken []byte, err error) {

	defer deferRecover(&err)

	previousTransformationPrivateKeyBuf := NewBufWithData(previousTransformationPrivateKey)
	newTransformationPrivateKeyBuf := NewBufWithData(newTransformationPrivateKey)
	passwordUpdateTokenBuf := NewBuf(BN_SIZE)

	defer deferClose(previousTransformationPrivateKeyBuf, newTransformationPrivateKeyBuf, passwordUpdateTokenBuf)

	pErr := C.virgil_pythia_get_password_update_token(
		previousTransformationPrivateKeyBuf.inBuf,
		newTransformationPrivateKeyBuf.inBuf,
		passwordUpdateTokenBuf.inBuf,
	)
	if pErr != 0 {
		err = NewPythiaError(int(pErr), "Internal Pythia error")
		return
	}

	return passwordUpdateTokenBuf.GetData(), nil
}

// UpdateDeblindedWithToken updates previously stored deblinded protected password with token.
// After this call, Transform() called with new arguments will return corresponding values
func (p *Pythia) UpdateDeblindedWithToken(
	deblindedPassword,
	passwordUpdateToken []byte,
) (updatedDeblindedPassword []byte, err error) {

	defer deferRecover(&err)

	deblindedPasswordBuf := NewBufWithData(deblindedPassword)
	passwordUpdateTokenBuf := NewBufWithData(passwordUpdateToken)
	updatedDeblindedPasswordBuf := NewBuf(GT_SIZE)

	defer deferClose(deblindedPasswordBuf, passwordUpdateTokenBuf, updatedDeblindedPasswordBuf)

	pErr := C.virgil_pythia_update_deblinded_with_token(
		deblindedPasswordBuf.inBuf,
		passwordUpdateTokenBuf.inBuf,
		updatedDeblindedPasswordBuf.inBuf,
	)
	if pErr != 0 {
		err = NewPythiaError(int(pErr), "Internal Pythia error")
		return
	}

	return updatedDeblindedPasswordBuf.GetData(), nil
}

func (p *Pythia) GenerateKeypair(keypairType crypto.KeyType, seed []byte) (keypair crypto.Keypair, err error) {
	crypto := cryptocgo.NewVirgilCrypto()
	err = crypto.SetKeyType(keypairType)
	if err != nil {
		return nil, err
	}
	return crypto.GenerateKeypairFromKeyMaterial(seed)
}

func deferRecover(err *error) {
	if r := recover(); r != nil {
		var ok bool
		*err, ok = r.(error)
		if !ok {
			*err = fmt.Errorf("pkg: %v", r)
		}
	}
}

type closer interface {
	Close()
}

func deferClose(closers ...closer) {
	for _, c := range closers {
		c.Close()
	}
}