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

package crypto_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/VirgilSecurity/virgil-sdk-go/crypto"
)

func TestSignVerify(t *testing.T) {
	var vcrypto crypto.Crypto

	//make random data
	data := make([]byte, 257)
	rand.Read(data)

	signerKey, err := vcrypto.GenerateKeypair()
	require.NoError(t, err)

	sign, err := vcrypto.Sign(data, signerKey)
	require.NoError(t, err)

	err = vcrypto.VerifySignature(data, sign, signerKey.PublicKey())
	assert.NoError(t, err)
}

func TestEncryptDecrypt(t *testing.T) {
	var vcrypto crypto.Crypto

	//make random data
	data := make([]byte, 257)
	rand.Read(data)

	encryptKey, err := vcrypto.GenerateKeypair()
	require.NoError(t, err)

	cipherText, err := vcrypto.Encrypt(data, encryptKey.PublicKey())
	require.NoError(t, err)

	actualData, err := vcrypto.Decrypt(cipherText, encryptKey)
	assert.NoError(t, err)
	assert.Equal(t, data, actualData)
}

func TestStreamCipher(t *testing.T) {
	var vcrypto crypto.Crypto
	key, err := vcrypto.GenerateKeypair()
	require.NoError(t, err)

	plainBuf := make([]byte, 102301)
	rand.Read(plainBuf)

	plain := bytes.NewReader(plainBuf)
	cipheredStream := bytes.NewBuffer(nil)
	err = vcrypto.EncryptStream(plain, cipheredStream, key.PublicKey())
	require.NoError(t, err)

	t.Logf("encrypted data: %s", base64.StdEncoding.EncodeToString(cipheredStream.Bytes()))

	//decrypt with key
	cipheredInputStream := bytes.NewReader(cipheredStream.Bytes())
	plainOutBuffer := bytes.NewBuffer(nil)
	err = vcrypto.DecryptStream(cipheredInputStream, plainOutBuffer, key)
	assert.NoError(t, err, "decrypt with correct key")
	assert.Equal(t, plainBuf, plainOutBuffer.Bytes(), "decrypt with correct key: plain & decrypted buffers do not match")

	//decrypt with wrong id must fail
	wrongKey, err := vcrypto.GenerateKeypair()
	require.NoError(t, err)

	cipheredInputStream = bytes.NewReader(cipheredStream.Bytes())
	plainOutBuffer = bytes.NewBuffer(nil)

	err = vcrypto.DecryptStream(cipheredInputStream, plainOutBuffer, wrongKey)
	assert.Error(t, err, "decrypt with incorrect key")
}

func TestStreamSigner(t *testing.T) {
	var vcrypto crypto.Crypto
	key, err := vcrypto.GenerateKeypair()
	require.NoError(t, err)

	plainBuf := make([]byte, 1023)
	rand.Read(plainBuf)
	plain := bytes.NewBuffer(plainBuf)
	sign, err := vcrypto.SignStream(plain, key)
	require.NoError(t, err)

	//verify signature
	plain = bytes.NewBuffer(plainBuf)
	err = vcrypto.VerifyStream(plain, sign, key.PublicKey())
	assert.NoError(t, err)

	//verify with wrong key must fail
	wrongKey, err := vcrypto.GenerateKeypair()
	require.NoError(t, err)

	err = vcrypto.VerifyStream(plain, sign, wrongKey.PublicKey())
	assert.Error(t, crypto.ErrSignVerification, err)

	//verify with wrong signature must fail
	plain = bytes.NewBuffer(plainBuf)
	sign[len(sign)-1] = ^sign[len(sign)-1] //invert last byte

	err = vcrypto.VerifyStream(plain, sign, wrongKey.PublicKey())
	assert.Equal(t, crypto.ErrSignVerification, err)
}

func TestExportImportKeys(t *testing.T) {
	var vcrypto crypto.Crypto
	key, err := vcrypto.GenerateKeypair()
	require.NoError(t, err)

	pubb, err := vcrypto.ExportPublicKey(key.PublicKey())
	assert.NoError(t, err)

	privb, err := vcrypto.ExportPrivateKey(key)
	assert.NoError(t, err)

	pub, err := vcrypto.ImportPublicKey(pubb)
	assert.NoError(t, err)

	priv, err := vcrypto.ImportPrivateKey(privb)
	assert.NoError(t, err)

	data := make([]byte, 257)
	rand.Read(data)

	// check that import keys was correct
	{
		cipherText, err := vcrypto.SignThenEncrypt(data, key, key.PublicKey())
		require.NoError(t, err)

		plaintext, err := vcrypto.DecryptThenVerify(cipherText, priv, pub)
		require.NoError(t, err)
		require.Equal(t, plaintext, data)
	}
}

func TestSignAndEncryptAndDecryptAndVerify(t *testing.T) {
	var vcrypto crypto.Crypto

	signKey, err := vcrypto.GenerateKeypair()
	require.NoError(t, err)

	encryptKey, err := vcrypto.GenerateKeypair()
	require.NoError(t, err)

	data := make([]byte, 257)
	rand.Read(data)

	cipherText, err := vcrypto.SignAndEncrypt(data, signKey, encryptKey.PublicKey())
	require.NoError(t, err)

	plaintext, err := vcrypto.DecryptAndVerify(cipherText, encryptKey, signKey.PublicKey(), encryptKey.PublicKey())
	require.NoError(t, err)
	require.Equal(t, data, plaintext)
}

func TestSignThenEncryptAndDecryptThenVerify(t *testing.T) {
	var vcrypto crypto.Crypto

	signKey, err := vcrypto.GenerateKeypair()
	require.NoError(t, err)

	encryptKey, err := vcrypto.GenerateKeypair()
	require.NoError(t, err)

	data := make([]byte, 257)
	rand.Read(data)

	cipherText, err := vcrypto.SignThenEncrypt(data, signKey, encryptKey.PublicKey())
	require.NoError(t, err)

	plaintext, err := vcrypto.DecryptThenVerify(cipherText, encryptKey, signKey.PublicKey(), encryptKey.PublicKey())
	require.NoError(t, err)
	require.Equal(t, data, plaintext)
}

func TestGenerateKeypairFromKeyMaterial(t *testing.T) {
	seed := make([]byte, 384)
	for i := range seed {
		seed[i] = byte(i)
	}

	pub1, priv1 := GenKeysFromSeed(t, seed)

	for i := 0; i < 10; i++ {
		pub2, priv2 := GenKeysFromSeed(t, seed)
		require.Equal(t, pub1, pub2)
		require.Equal(t, priv1, priv2)
	}

	// check if we change seed than key pair is different
	{
		seed[383]++
		pub3, priv3 := GenKeysFromSeed(t, seed)
		require.NotEqual(t, pub1, pub3)
		require.NotEqual(t, priv1, priv3)
	}
}

func GenKeysFromSeed(t *testing.T, seed []byte) (publicKey []byte, privateKey []byte) {
	var vcrypto crypto.Crypto
	key, err := vcrypto.GenerateKeypairFromKeyMaterial(seed)
	require.NoError(t, err)

	publicKey, err = vcrypto.ExportPublicKey(key.PublicKey())
	require.NoError(t, err)

	privateKey, err = vcrypto.ExportPrivateKey(key)
	require.NoError(t, err)

	return publicKey, privateKey
}

func TestGenerateKeypairFromKeyMaterialBadCase(t *testing.T) {
	table := []struct {
		name string
		size int
	}{
		{"less 32", 31},
		{"greater 512", 513},
	}
	var vcrypto crypto.Crypto

	for _, test := range table {
		data, err := vcrypto.Random(test.size)
		require.NoError(t, err)

		_, err = vcrypto.GenerateKeypairFromKeyMaterial(data)
		assert.Equal(t, crypto.ErrInvalidSeedSize, err, test.name)
	}
}

func TestKeyTypes(t *testing.T) {
	var vcrypto crypto.Crypto
	m, err := vcrypto.Random(128)
	require.NoError(t, err)

	table := []struct {
		kt            crypto.KeyType
		expectedError error
	}{
		{crypto.DefaultKeyType, nil},
		{crypto.RSA_2048, nil},
		// {crypto.RSA_3072, nil},
		// {crypto.RSA_4096, nil},
		// {crypto.RSA_8192, nil},
		{crypto.EC_SECP256R1, nil},
		{crypto.EC_CURVE25519, nil},
		{crypto.FAST_EC_ED25519, nil},
		{crypto.KeyType(100), crypto.ErrUnsupportedKeyType},
	}

	fs := []func(kt crypto.KeyType) error{
		func(kt crypto.KeyType) error {
			vcrypto.KeyType = kt
			_, err := vcrypto.GenerateKeypair()
			return err
		},
		func(kt crypto.KeyType) error {
			_, err := vcrypto.GenerateKeypairFromKeyMaterialForType(kt, m)
			return err
		},
	}
	for _, test := range table {
		for _, f := range fs {
			err := f(test.kt)
			assert.Equal(t, test.expectedError, err, test.kt)
		}
	}
}
