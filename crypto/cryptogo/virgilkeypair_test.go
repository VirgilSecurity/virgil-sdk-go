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
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKeys(t *testing.T) {
	keypair, err := NewKeypair()
	if err != nil {
		t.Fatal(err)
	}
	pus1, err := keypair.PublicKey().Encode()
	if err != nil {
		t.Fatal(err)
	}
	prs1, err := keypair.PrivateKey().Encode(nil)
	if err != nil {
		t.Fatal(err)
	}

	dPub, err := DecodePublicKey(pus1)
	if err != nil {
		t.Fatal(err)
	}
	dPriv, err := DecodePrivateKey(prs1, nil)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(keypair.PublicKey().contents(), dPub.contents()) {
		t.Log(keypair.PublicKey().contents())
		t.Log(dPub.contents())

		t.Fatal("deserialized & original public keys do not match")
	}

	if !bytes.Equal(keypair.PrivateKey().contents(), dPriv.contents()) {
		t.Fatal("deserialized & original private keys do not match")
	}

	//check password
	passBytes := make([]byte, 12)
	readRandom(t, passBytes)
	prs1, err = dPriv.Encode(passBytes)
	if err != nil {
		t.Fatal(err)
	}

	dPriv, err = DecodePrivateKey(prs1, passBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keypair.PrivateKey().contents(), dPriv.contents()) {
		t.Fatal("keys do not match")
	}
}

func readRandom(tb testing.TB, dst []byte) {
	_, err := rand.Read(dst)
	assert.NoError(tb, err)
}
