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

	"github.com/VirgilSecurity/virgil-sdk-go/crypto/cryptogo/gcm"
)

func TestStream(t *testing.T) {
	symmetricKey := make([]byte, 32) //256 bit AES key
	nonce := make([]byte, 12)        //96 bit AES GCM nonce

	rand.Reader.Read(symmetricKey)
	rand.Reader.Read(nonce)

	sc := StreamCipher

	plain := make([]byte, gcm.GcmStreamBufSize*2-20)
	rand.Reader.Read(plain)
	ad := make([]byte, 1)
	rand.Reader.Read(ad)
	for i := 0; i < 40; i++ {

		in := bytes.NewBuffer(plain)
		out := &bytes.Buffer{}
		err := sc.Encrypt(symmetricKey, nonce, ad, in, out)
		if err != nil {
			t.Fatalf("%+v", err)
		}
		plainOut := &bytes.Buffer{}

		err = sc.Decrypt(symmetricKey, nonce, ad, out, plainOut)
		if err != nil {
			t.Fatalf("%d, %+v", i, err)
		}
		if bytes.Compare(plain, plainOut.Bytes()) != 0 {
			t.Fatal("plaintext and decrypted text do not match")
		}
		plain = append(plain, ad...)
	}
}

func TestChunk(t *testing.T) {
	symmetricKey := make([]byte, 32) //256 bit AES key
	nonce := make([]byte, 12)        //96 bit AES GCM nonce

	rand.Reader.Read(symmetricKey)
	rand.Reader.Read(nonce)

	sc := ChunkCipher
	plain := make([]byte, gcm.GcmStreamBufSize*3-20)
	rand.Reader.Read(plain)
	ad := make([]byte, 1)
	rand.Reader.Read(ad)
	for i := 0; i < 40; i++ {
		in := bytes.NewBuffer(plain)
		out := &bytes.Buffer{}
		err := sc.Encrypt(symmetricKey, nonce, ad, DefaultChunkSize, in, out)
		if err != nil {
			t.Fatalf("%+v", err)
		}
		plainOut := &bytes.Buffer{}

		err = sc.Decrypt(symmetricKey, nonce, ad, DefaultChunkSize, out, plainOut)
		if err != nil {
			t.Fatalf("%d, %+v", i, err)
		}
		if bytes.Compare(plain, plainOut.Bytes()) != 0 {
			t.Fatal("plaintext and decrypted text do not match")
		}
		plain = append(plain, ad...)
	}
}
