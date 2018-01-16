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

package cryptonative

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func testEncryptWithKey(data []byte, key PublicKey) {

	cipher := NewCipher()
	cipher.AddKeyRecipient(key.(*ed25519PublicKey))
	_, err := cipher.Encrypt(data)
	if err != nil {
		panic(err)
	}
}
func BenchmarkEncrypt(b *testing.B) {

	data := make([]byte, 257)
	rand.Read(data)

	kp, err := NewKeypair()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		testEncryptWithKey(data, kp.PublicKey())
	}
}
func testDecryptWithKey(data []byte, key PrivateKey) {

	_, err := NewCipher().DecryptWithPrivateKey(data, key.(*ed25519PrivateKey))
	if err != nil {
		panic(err)
	}
}
func BenchmarkDecrypt(b *testing.B) {

	data := make([]byte, 257)
	rand.Read(data)

	keypair, err := NewKeypair()
	if err != nil {
		b.Fatal(err)
	}

	cipher := NewCipher()
	cipher.AddKeyRecipient(keypair.PublicKey().(*ed25519PublicKey))
	ciphertext, err := cipher.Encrypt(data)
	if err != nil {
		panic(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		testDecryptWithKey(ciphertext, keypair.PrivateKey())
	}
}
func BenchmarkSign(b *testing.B) {

	data := make([]byte, 257)
	rand.Read(data)

	keypair, err := NewKeypair()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Signer.Sign(data, keypair.PrivateKey())
		if err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkVerify(b *testing.B) {

	data := make([]byte, 257)
	rand.Read(data)

	keypair, err := NewKeypair()
	if err != nil {
		b.Fatal(err)
	}
	signature, err := Signer.Sign(data, keypair.PrivateKey())
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := Verifier.Verify(data, keypair.PublicKey(), signature)
		if err != nil {
			b.Fatal(err)
		}
	}
}
func TestCMS(t *testing.T) {

	//make random data
	data := make([]byte, 257)
	rand.Read(data)

	keypair, err := NewKeypair()
	if err != nil {
		t.Fatal(err)
	}

	//make random password
	passBytes := make([]byte, 12)
	rand.Read(passBytes)

	cipher := NewCipher()
	cipher.AddPasswordRecipient(passBytes)
	cipher.AddKeyRecipient(keypair.PublicKey().(*ed25519PublicKey))
	cipherText, err := cipher.Encrypt(data)
	if err != nil {
		t.Fatal(err)
	}
	if plaintext, err := cipher.DecryptWithPassword(cipherText, passBytes); err != nil || !bytes.Equal(plaintext, data) {
		t.Fatal(err)
	}
	if plaintext, err := cipher.DecryptWithPrivateKey(cipherText, keypair.PrivateKey().(*ed25519PrivateKey)); err != nil || !bytes.Equal(plaintext, data) {
		t.Fatal(err)
	}

	signerKeypair, err := NewKeypair()
	if err != nil {
		t.Fatal(err)
	}

	cipherText, err = cipher.SignThenEncrypt(data, signerKeypair.PrivateKey().(*ed25519PrivateKey))
	if err != nil {
		t.Fatal(err)
	}

	if plaintext, err := NewCipher().DecryptThenVerify(cipherText, keypair.PrivateKey().(*ed25519PrivateKey), keypair.PublicKey().(*ed25519PublicKey), signerKeypair.PublicKey().(*ed25519PublicKey)); err != nil || !bytes.Equal(plaintext, data) {
		t.Fatal(err)
	}

}
func TestStreamCipher(t *testing.T) {
	keypair, err := NewKeypair()
	if err != nil {
		t.Fatal(err)
	}

	//make random password
	passBytes := make([]byte, 12)
	rand.Read(passBytes)

	cipher := NewCipher()
	cipher.AddKeyRecipient(keypair.PublicKey().(*ed25519PublicKey))

	plainBuf := make([]byte, 1023)
	rand.Read(plainBuf)
	plain := bytes.NewBuffer(plainBuf)
	cipheredStream := &bytes.Buffer{}
	err = cipher.EncryptStream(plain, cipheredStream)
	if err != nil {
		t.Fatal(err)
	}

	//decrypt with key

	cipheredInputStream := bytes.NewBuffer(cipheredStream.Bytes())
	plainOutBuffer := &bytes.Buffer{}
	err = cipher.DecryptStream(cipheredInputStream, plainOutBuffer, keypair.PrivateKey().(*ed25519PrivateKey))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plainBuf, plainOutBuffer.Bytes()) {
		t.Fatal("plain & decrypted buffers do not match")
	}

	//decrypt with wrong id must fail

	cipheredInputStream = bytes.NewBuffer(cipheredStream.Bytes())
	plainOutBuffer = &bytes.Buffer{}

	keypair, err = NewKeypair()
	if err != nil {
		t.Fatal(err)
	}
	err = cipher.DecryptStream(cipheredInputStream, plainOutBuffer, keypair.PrivateKey().(*ed25519PrivateKey))
	if err == nil {
		t.Fatal("decrypt must fail but didn't")
	}

	//decrypt with wrong key must fail
	keypair1, err := NewKeypair()

	if err != nil {
		t.Fatal(err)
	}
	cipheredInputStream = bytes.NewBuffer(cipheredStream.Bytes())
	plainOutBuffer = &bytes.Buffer{}
	err = cipher.DecryptStream(cipheredInputStream, plainOutBuffer, keypair1.PrivateKey().(*ed25519PrivateKey))
	if err == nil {
		t.Fatal("decrypt must fail but didn't")
	}

}
