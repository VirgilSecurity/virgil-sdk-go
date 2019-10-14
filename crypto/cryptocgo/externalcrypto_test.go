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
	"bytes"
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSignEncrypt(t *testing.T) {
	crypto := &ExternalCrypto{}

	//make random data
	data := make([]byte, 257)
	rand.Read(data)

	keypair, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	signerKeypair, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	cipherText, err := crypto.SignThenEncrypt(data, signerKeypair.PrivateKey(), keypair.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	if plaintext, err := crypto.DecryptThenVerify(cipherText, keypair.PrivateKey(), keypair.PublicKey(), signerKeypair.PublicKey()); err != nil || !bytes.Equal(plaintext, data) {
		t.Fatal(err)
	}

}

func BenchmarkSign(b *testing.B) {
	crypto := &ExternalCrypto{}

	//make random data
	data := make([]byte, 257)
	rand.Read(data)

	signerKeypair, err := crypto.GenerateKeypair()
	if err != nil {
		b.Fatal(err)
	}

	sign, err := crypto.Sign(data, signerKeypair.PrivateKey())
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		crypto.VerifySignature(data,sign, signerKeypair.publicKey)
	}
}

func BenchmarkSignThenEncrypt(b *testing.B) {

	crypto := &ExternalCrypto{}

	//make random data
	data := make([]byte, 257)
	rand.Read(data)

	keypair, err := crypto.GenerateKeypair()
	if err != nil {
		b.Fatal(err)
	}

	signerKeypair, err := crypto.GenerateKeypair()
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		cipherText, err := crypto.SignThenEncrypt(data, signerKeypair.PrivateKey(), keypair.PublicKey())
		if err != nil {
			b.Fatal(err)
		}
		if plaintext, err := crypto.DecryptThenVerify(cipherText, keypair.PrivateKey(), signerKeypair.PublicKey()); err != nil || !bytes.Equal(plaintext, data) {
			b.Fatal(err)
		}
	}

}

func TestStreamCipher(t *testing.T) {
	crypto := &ExternalCrypto{}
	keypair, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	plainBuf := make([]byte, 102301)
	rand.Read(plainBuf)
	plain := bytes.NewBuffer(plainBuf)
	cipheredStream := &bytes.Buffer{}
	err = crypto.EncryptStream(plain, cipheredStream, keypair.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	//decrypt with key

	cipheredInputStream := bytes.NewBuffer(cipheredStream.Bytes())
	plainOutBuffer := &bytes.Buffer{}
	err = crypto.DecryptStream(cipheredInputStream, plainOutBuffer, keypair.PrivateKey())
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plainBuf, plainOutBuffer.Bytes()) {
		t.Fatal("plain & decrypted buffers do not match")
	}

	//decrypt with wrong id must fail

	cipheredInputStream = bytes.NewBuffer(cipheredStream.Bytes())
	plainOutBuffer = &bytes.Buffer{}

	keypair, err = crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	err = crypto.DecryptStream(cipheredInputStream, plainOutBuffer, keypair.PrivateKey())
	if err == nil {
		t.Fatal("decrypt must fail but didn't")
	}

	//decrypt with wrong key must fail
	keypair1, err := crypto.GenerateKeypair()

	if err != nil {
		t.Fatal(err)
	}
	cipheredInputStream = bytes.NewBuffer(cipheredStream.Bytes())
	plainOutBuffer = &bytes.Buffer{}
	err = crypto.DecryptStream(cipheredInputStream, plainOutBuffer, keypair1.PrivateKey())
	if err == nil {
		t.Fatal("decrypt must fail but didn't")
	}

}

func TestStreamSigner(t *testing.T) {
	crypto := &ExternalCrypto{}
	keypair, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	plainBuf := make([]byte, 1023)
	rand.Read(plainBuf)
	plain := bytes.NewBuffer(plainBuf)
	sign, err := crypto.SignStream(plain, keypair.PrivateKey())
	if err != nil {
		t.Fatal(err)
	}

	//verify signature

	plain = bytes.NewBuffer(plainBuf)

	res, err := crypto.VerifyStream(plain, sign, keypair.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	if !res {
		t.Fatal("verify result is ok but err is nil")
	}

	//verify with wrong signature must fail

	plain = bytes.NewBuffer(plainBuf)

	sign[len(sign)-1] = ^sign[len(sign)-1] //invert last byte

	res, err = crypto.VerifyStream(plain, sign, keypair.PublicKey())
	if res {
		t.Fatal("verify must fail but didn't")
	}

	sign[len(sign)-1] = ^sign[len(sign)-1] //restore last byte
	//verify with wrong key must fail
	keypair, err = crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	res, err = crypto.VerifyStream(plain, sign, keypair.PublicKey())
	if res {
		t.Fatal("verify must fail but didn't")
	}

}

func TestNativeCrypto_ExportImportPrivateKey(t *testing.T) {
	crypto := &ExternalCrypto{}
	keypair, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	pubb, err := crypto.ExportPublicKey(keypair.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	privb, err := crypto.ExportPrivateKey(keypair.PrivateKey(), "abc")
	if err != nil {
		t.Fatal(err)
	}

	pub, err := crypto.ImportPublicKey(pubb)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := crypto.ImportPrivateKey(privb, "abc")
	if err != nil {
		t.Fatal(err)
	}

	data := make([]byte, 257)
	rand.Read(data)

	cipherText, err := crypto.SignThenEncrypt(data, keypair.PrivateKey(), keypair.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	if plaintext, err := crypto.DecryptThenVerify(cipherText, priv, pub, pub); err != nil || !bytes.Equal(plaintext, data) {
		t.Fatal(err)
	}

}

func TestExternalCrypto_GenerateKeypairFromKeyMaterial(t *testing.T) {


	seed := make([]byte, 384)
	for i := range seed {
		seed[i] = byte(i)
	}

	pub1, priv1, err := GenKeysFromSeed(seed)
	assert.NoError(t, err)

	for i := 0; i < 10; i++ {
		pub2, priv2, err := GenKeysFromSeed(seed)
		assert.NoError(t, err)
		assert.Equal(t, pub1, pub2)
		assert.Equal(t, priv1, priv2)
	}

	seed[383] = seed[383] + 1
	pub3, priv3, err := GenKeysFromSeed(seed)
	assert.NoError(t, err)

	assert.NotEqual(t, pub1, pub3)
	assert.NotEqual(t, priv1, priv3)
}

func GenKeysFromSeed(seed []byte) (publicKey []byte, privateKey []byte, err error) {
	crypto := &ExternalCrypto{}
	keypair, err := crypto.GenerateKeypairFromKeyMaterial(seed)
	if err != nil {
		return
	}

	publicKey, err = crypto.ExportPublicKey(keypair.PublicKey())
	if err != nil {
		return
	}

	privateKey, err = crypto.ExportPrivateKey(keypair.PrivateKey(), "")
	return
}

func TestExternalCrypto_ImportPublicKey(t *testing.T) {
	crypto := &ExternalCrypto{}

	keypair, err := crypto.GenerateKeypair()
	assert.NoError(t, err)

	pkDer, err := crypto.ExportPublicKey(keypair.PublicKey())

	assert.NoError(t, err)

	pk, err := crypto.ImportPublicKey(pkDer)
	assert.NoError(t, err)
	assert.NotNil(t, pk)

	pk, err = crypto.ImportPublicKey([]byte{1,2,3,4,5,6})

	assert.Nil(t, pk)
	assert.Error(t, err)

}