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
 *
 */

package cryptogo

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"

	"golang.org/x/crypto/hkdf"
)

type (
	PFSSession struct {
		SKa, SKb, AD, SessionID []byte
		Initiator               bool
	}

	PFS interface {
		StartPFSSession(ICb, LTCb, OTCb *ed25519PublicKey, ICa, EKa *ed25519PrivateKey, additionalData []byte) (sess *PFSSession, err error)
		ReceivePFCSession(ICa, EKa *ed25519PublicKey, ICb, LTCb, OTCb *ed25519PrivateKey, additionalData []byte) (sess *PFSSession, err error)
	}
)

var virgil = []byte("Virgil")

func (c *VirgilCrypto) StartPFSSession(
	ICb *ed25519PublicKey,
	LTCb *ed25519PublicKey,
	OTCb *ed25519PublicKey,
	ICa *ed25519PrivateKey,
	EKa *ed25519PrivateKey,
	additionalData []byte,
) (sess *PFSSession, err error) {

	sk, err := EDHInit(ICa, EKa, ICb, LTCb, OTCb)
	if err != nil {
		return
	}

	return c.makeSession(sk, additionalData, true), nil
}

func (c *VirgilCrypto) ReceivePFCSession(
	ICa *ed25519PublicKey,
	EKa *ed25519PublicKey,
	ICb *ed25519PrivateKey,
	LTCb *ed25519PrivateKey,
	OTCb *ed25519PrivateKey,
	additionalData []byte,
) (sess *PFSSession, err error) {

	sk, err := EDHRespond(ICa, EKa, ICb, LTCb, OTCb)
	if err != nil {
		return nil, err
	}

	return c.makeSession(sk, additionalData, false), nil

}

func (c *VirgilCrypto) makeSession(sk []byte, additionalData []byte, initiator bool) *PFSSession {
	ska, skb := sk[:64], sk[64:]

	toHash := make([]byte, 0, len(additionalData)+len(virgil))
	toHash = append(toHash, additionalData...)
	toHash = append(toHash, virgil...)

	hash := sha256.Sum256(toHash)

	ad := hash[:]

	toHash = make([]byte, 0, len(sk)+len(ad)+len(virgil))
	toHash = append(toHash, sk...)
	toHash = append(toHash, ad...)
	toHash = append(toHash, virgil...)

	sessHash := sha256.Sum256(toHash)
	sessionID := sessHash[:]

	return &PFSSession{
		Initiator: initiator,
		SKa:       ska,
		SKb:       skb,
		AD:        ad,
		SessionID: sessionID,
	}
}

func (s *PFSSession) Encrypt(plaintext []byte) (salt, ciphertext []byte) {
	salt = make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		panic(err)
	}

	keyAndNonce := make([]byte, 44)

	sk := s.SKa

	if !s.Initiator {
		sk = s.SKb
	}

	kdf := hkdf.New(sha256.New, sk, salt, virgil)

	_, err = kdf.Read(keyAndNonce)
	if err != nil {
		panic(err)
	}

	ciph, _ := aes.NewCipher(keyAndNonce[:32])
	aesGCM, _ := cipher.NewGCM(ciph)
	ciphertext = aesGCM.Seal(nil, keyAndNonce[32:], plaintext, s.AD)
	return
}

func (s *PFSSession) Decrypt(salt, ciphertext []byte) ([]byte, error) {

	keyAndNonce := make([]byte, 44)

	sk := s.SKb

	if !s.Initiator {
		sk = s.SKa
	}

	kdf := hkdf.New(sha256.New, sk, salt, virgil)

	_, err := kdf.Read(keyAndNonce)
	if err != nil {
		panic(err)
	}

	ciph, _ := aes.NewCipher(keyAndNonce[:32])
	aesGCM, _ := cipher.NewGCM(ciph)
	return aesGCM.Open(nil, keyAndNonce[32:], ciphertext, s.AD)
}
