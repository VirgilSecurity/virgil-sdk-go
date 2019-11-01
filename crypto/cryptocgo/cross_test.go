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
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/VirgilSecurity/virgil-sdk-go/crypto/cryptogo"
)

func TestCrossTestCrypto(t *testing.T) {
	c1 := &cryptogo.VirgilCrypto{}
	c2 := &ExternalCrypto{}

	kp1, err := c1.GenerateKeypair()
	assert.NoError(t, err)

	kp2, err := c2.GenerateKeypair()
	assert.NoError(t, err)

	data := make([]byte, 257)
	readRandom(t, data)

	kp2p, err := c2.ExportPublicKey(kp2.PublicKey())
	assert.NoError(t, err)

	kp2pub, err := c1.ImportPublicKey(kp2p)
	assert.NoError(t, err)

	ciphertext, err := c1.SignThenEncrypt(data, kp1.PrivateKey(), kp2pub)
	assert.NoError(t, err)

	kp1p, err := c1.ExportPublicKey(kp1.PublicKey())
	assert.NoError(t, err)

	kp1pub, err := c2.ImportPublicKey(kp1p)
	assert.NoError(t, err)

	decrypted, err := c2.DecryptThenVerify(ciphertext, kp2.PrivateKey(), kp1pub)
	assert.NoError(t, err)
	assert.Equal(t, decrypted, data)
}

func TestTokenSigner(t *testing.T) {
	c1 := &ExternalCrypto{}
	c2 := &cryptogo.VirgilCrypto{}

	v1 := NewVirgilAccessTokenSigner()
	v2 := cryptogo.NewVirgilAccessTokenSigner()

	kp1, err := c1.GenerateKeypair()
	assert.NoError(t, err)

	exported, err := c1.ExportPrivateKey(kp1.PrivateKey(), "")
	assert.NoError(t, err)

	sk2, err := c2.ImportPrivateKey(exported, "")
	assert.NoError(t, err)

	pk2, err := c2.ExtractPublicKey(sk2)
	assert.NoError(t, err)

	data := make([]byte, 257)
	readRandom(t, data)

	sig1, err := v1.GenerateTokenSignature(data, kp1.PrivateKey())
	assert.NoError(t, err)

	err = v2.VerifyTokenSignature(data, sig1, pk2)
	assert.NoError(t, err)
}

func BenchmarkVirgilAccessTokenSigner_VerifyTokenSignature(b *testing.B) {
	c1 := &ExternalCrypto{}
	kp1, err := c1.GenerateKeypair()
	assert.NoError(b, err)
	data := make([]byte, 257)
	readRandom(b, data)

	v1 := NewVirgilAccessTokenSigner()
	sig1, err := v1.GenerateTokenSignature(data, kp1.PrivateKey())
	assert.NoError(b, err)

	for i := 0; i < b.N; i++ {
		err = v1.VerifyTokenSignature(data, sig1, kp1.PublicKey())
		assert.NoError(b, err)
	}
}

func BenchmarkInternalVirgilAccessTokenSigner_VerifyTokenSignature(b *testing.B) {
	c1 := &cryptogo.VirgilCrypto{}
	kp1, err := c1.GenerateKeypair()
	assert.NoError(b, err)
	data := make([]byte, 257)
	readRandom(b, data)

	v1 := cryptogo.NewVirgilAccessTokenSigner()
	sig1, err := v1.GenerateTokenSignature(data, kp1.PrivateKey())
	assert.NoError(b, err)

	for i := 0; i < b.N; i++ {
		err = v1.VerifyTokenSignature(data, sig1, kp1.PublicKey())
		if err != nil {
			b.Fatal(err)
		}
	}
}

func readRandom(tb testing.TB, dst []byte) {
	_, err := rand.Read(dst)
	assert.NoError(tb, err)
}
