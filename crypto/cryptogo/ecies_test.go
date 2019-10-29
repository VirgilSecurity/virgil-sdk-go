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

package cryptogo

import (
	"bytes"
	"testing"

	"github.com/agl/ed25519/extra25519"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
)

func TestECIES(t *testing.T) {

	kp, err := NewKeypair()
	if err != nil {
		t.Fatal(err)
	}
	symmetricKey := make([]byte, 32)
	readRandom(t, symmetricKey)

	encryptedSymmetricKey, tag, ephPub, iv, err := encryptSymmetricKeyWithECIES(kp.PublicKey().contents(), symmetricKey)

	if err != nil {
		t.Fatal(err)
	}

	decryptedKey, err := decryptSymmetricKeyWithECIES(encryptedSymmetricKey, tag, ephPub, iv, kp.PrivateKey().contents())

	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(symmetricKey, decryptedKey) {
		t.Fatal("symmetric key and decrypted key are different")
	}
}

func TestEdToCurve(t *testing.T) {
	ephKeypair, err := NewKeypair()
	if err != nil {
		t.Fatal(err)
	}
	hisKeypair, err := NewKeypair()
	if err != nil {
		t.Fatal(err)
	}
	ephPrivate := new([ed25519.PrivateKeySize]byte)
	ephCurvePrivate := new([Curve25519PrivateKeySize]byte)
	ephPublic := new([ed25519.PublicKeySize]byte)
	ephCurvePublic := new([Curve25519PublicKeySize]byte)

	hisPrivate := new([ed25519.PrivateKeySize]byte)
	hisCurvePrivate := new([Curve25519PrivateKeySize]byte)
	hisPublic := new([ed25519.PublicKeySize]byte)
	hisCurvePublic := new([Curve25519PublicKeySize]byte)

	copy(hisPrivate[:], hisKeypair.PrivateKey().contents())
	copy(hisPublic[:], hisKeypair.PublicKey().contents())
	copy(ephPrivate[:], ephKeypair.PrivateKey().contents())
	copy(ephPublic[:], ephKeypair.PublicKey().contents())

	extra25519.PrivateKeyToCurve25519(ephCurvePrivate, ephPrivate)
	extra25519.PublicKeyToCurve25519(hisCurvePublic, hisPublic)

	extra25519.PrivateKeyToCurve25519(hisCurvePrivate, hisPrivate)
	extra25519.PublicKeyToCurve25519(ephCurvePublic, ephPublic)

	sharedSecret1 := new([Curve25519SharedKeySize]byte)
	curve25519.ScalarMult(sharedSecret1, ephCurvePrivate, hisCurvePublic)
	sharedSecret2 := new([Curve25519SharedKeySize]byte)
	curve25519.ScalarMult(sharedSecret2, hisCurvePrivate, ephCurvePublic)

	zeroSecret := new([Curve25519SharedKeySize]byte)
	if bytes.Equal(zeroSecret[:], sharedSecret1[:]) || (!bytes.Equal(sharedSecret1[:], sharedSecret2[:])) {
		t.Fatal("shared keys are different or all zeroes")
	}
}
