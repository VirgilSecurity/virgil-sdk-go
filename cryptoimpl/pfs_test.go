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

package cryptoimpl

import (
	"testing"

	"crypto/rand"

	"github.com/stretchr/testify/require"
)

func TestPFS(t *testing.T) {

	c := &VirgilCrypto{}

	//ICa, EKa, ICb, LTCb, OTCb
	ICa, err := c.GenerateKeypair()
	require.NoError(t, err)

	EKa, err := c.GenerateKeypair()
	require.NoError(t, err)

	ICb, err := c.GenerateKeypair()
	require.NoError(t, err)

	LTCb, err := c.GenerateKeypair()
	require.NoError(t, err)

	OTCb, err := c.GenerateKeypair()
	require.NoError(t, err)

	pfs := c

	ad := append(ICa.PublicKey().Identifier(), ICb.PublicKey().Identifier()...)

	sessA, err := pfs.StartPFSSession(ICb.PublicKey(), LTCb.PublicKey(), OTCb.PublicKey(), ICa.PrivateKey(), EKa.PrivateKey(), ad)
	require.NoError(t, err)

	sessB, err := pfs.ReceivePFCSession(ICa.PublicKey(), EKa.PublicKey(), ICb.PrivateKey(), LTCb.PrivateKey(), OTCb.PrivateKey(), ad)
	require.NoError(t, err)

	msg := make([]byte, 1025)
	rand.Read(msg)

	salt, ciphertext := sessA.Encrypt(msg)

	plaintext, err := sessB.Decrypt(salt, ciphertext)

	require.NoError(t, err)

	require.Equal(t, plaintext, msg)

	/*ICab, _ := c.ExportPrivateKey(ICa.PrivateKey(), "")
	EKab, _ := c.ExportPrivateKey(EKa.PrivateKey(), "")
	ICbb, _ := c.ExportPrivateKey(ICb.PrivateKey(), "")
	LTCbb, _ := c.ExportPrivateKey(LTCb.PrivateKey(), "")
	OTCbb, _ := c.ExportPrivateKey(OTCb.PrivateKey(), "")

	vec := map[string]interface{}{
		"ICa":            ICab,
		"EKa":            EKab,
		"ICb":            ICbb,
		"LTCb":           LTCbb,
		"OTCb":           OTCbb,
		"AdditionalData": append(ad, []byte("Virgil")...),
		"SKa":            sessA.SKa,
		"SKb":            sessA.SKb,
		"AD":             sessA.AD,
		"SessionID":      sessA.SessionID,
		"Salt":           salt,
		"Plaintext":      plaintext,
		"Ciphertext":     ciphertext,
	}

	res, _ := json.Marshal(vec)
	fmt.Printf("%s\n\n\n", res)*/

	salt, ciphertext = sessB.Encrypt(msg)

	plaintext, err = sessA.Decrypt(salt, ciphertext)

	require.NoError(t, err)

	require.Equal(t, plaintext, msg)

	plaintext, err = sessB.Decrypt(salt, ciphertext)

	require.Error(t, err)

	require.NotEqual(t, plaintext, msg)
}

func TestPFSNoOTC(t *testing.T) {

	c := &VirgilCrypto{}

	//ICa, EKa, ICb, LTCb, OTCb
	ICa, err := c.GenerateKeypair()
	require.NoError(t, err)

	EKa, err := c.GenerateKeypair()
	require.NoError(t, err)

	ICb, err := c.GenerateKeypair()
	require.NoError(t, err)

	LTCb, err := c.GenerateKeypair()
	require.NoError(t, err)

	pfs := c

	ad := append(ICa.PublicKey().Identifier(), ICb.PublicKey().Identifier()...)

	sessA, err := pfs.StartPFSSession(ICb.PublicKey(), LTCb.PublicKey(), nil, ICa.PrivateKey(), EKa.PrivateKey(), ad)
	require.NoError(t, err)

	sessB, err := pfs.ReceivePFCSession(ICa.PublicKey(), EKa.PublicKey(), ICb.PrivateKey(), LTCb.PrivateKey(), nil, ad)
	require.NoError(t, err)

	msg := make([]byte, 1025)
	rand.Read(msg)

	salt, ciphertext := sessA.Encrypt(msg)

	plaintext, err := sessB.Decrypt(salt, ciphertext)

	require.NoError(t, err)

	require.Equal(t, plaintext, msg)

	/*ICab, _ := c.ExportPrivateKey(ICa.PrivateKey(), "")
	EKab, _ := c.ExportPrivateKey(EKa.PrivateKey(), "")
	ICbb, _ := c.ExportPrivateKey(ICb.PrivateKey(), "")
	LTCbb, _ := c.ExportPrivateKey(LTCb.PrivateKey(), "")

	vec := map[string]interface{}{
		"ICa":         ICab,
		"EKa":         EKab,
		"ICb":         ICbb,
		"LTCb":        LTCbb,
		"AdditionalData": append(ad, []byte("Virgil")...),
		"SKa":         sessA.SKa,
		"SKb":         sessA.SKb,
		"AD":          sessA.AD,
		"SessionID":   sessA.SessionID,
		"Salt":        salt,
		"Plaintext":   plaintext,
		"Ciphertext":  ciphertext,
	}

	res, _ := json.Marshal(vec)
	fmt.Printf("%s", res)*/

	sessB.Initiator = !sessB.Initiator

	plaintext, err = sessB.Decrypt(salt, ciphertext)

	require.Error(t, err)

	require.NotEqual(t, plaintext, msg)

}
