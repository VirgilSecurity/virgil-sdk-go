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
	"io"

	"crypto/sha512"

	"github.com/minio/sha256-simd"
	"gopkg.in/virgil.v5/cryptoimpl/keytypes"
	"gopkg.in/virgil.v5/errors"
)

type (
	VirgilCrypto struct {
		MakeCipher            func() Cipher
		UseSHA256Fingerprints bool
	}
)

func (c *VirgilCrypto) SetKeyType(keyType KeyType) error {
	if keyType != keytypes.Default && keyType != keytypes.FAST_EC_ED25519 {
		return errors.New("Only ED25519 keys are supported")
	}
	return nil
}

func (c *VirgilCrypto) GenerateKeypair() (*ed25519Keypair, error) {

	keypair, err := NewKeypair()
	return keypair, err
}

func (c *VirgilCrypto) ImportPrivateKey(data []byte, password string) (*ed25519PrivateKey, error) {
	key, err := DecodePrivateKey(data, []byte(password))
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (c *VirgilCrypto) ImportPublicKey(data []byte) (*ed25519PublicKey, error) {
	key, err := DecodePublicKey(data)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (c *VirgilCrypto) ExportPrivateKey(key *ed25519PrivateKey, password string) ([]byte, error) {
	if key == nil || key.Empty() {
		return nil, errors.New("key is nil")
	}
	return key.Encode([]byte(password))
}

func (c *VirgilCrypto) ExportPublicKey(key *ed25519PublicKey) ([]byte, error) {
	if key == nil || key.Empty() {
		return nil, errors.New("key is nil")
	}
	return key.Encode()
}

func (c *VirgilCrypto) Encrypt(data []byte, recipients ...*ed25519PublicKey) ([]byte, error) {
	cipher := c.getCipher()
	for _, k := range recipients {
		if k == nil || k.Empty() {
			return nil, errors.New("key is nil")
		}
		cipher.AddKeyRecipient(k)
	}
	return cipher.Encrypt(data)
}

func (c *VirgilCrypto) EncryptStream(in io.Reader, out io.Writer, recipients ...*ed25519PublicKey) error {
	cipher := c.getCipher()
	for _, k := range recipients {
		if k == nil || k.Empty() {
			return errors.New("key is nil")
		}
		cipher.AddKeyRecipient(k)
	}
	return cipher.EncryptStream(in, out)
}

func (c *VirgilCrypto) Decrypt(data []byte, key *ed25519PrivateKey) ([]byte, error) {
	if key == nil || key.Empty() {
		return nil, errors.New("key is nil")
	}
	return c.MakeCipher().DecryptWithPrivateKey(data, key)
}

func (c *VirgilCrypto) DecryptStream(in io.Reader, out io.Writer, key *ed25519PrivateKey) error {
	if key == nil || key.Empty() {
		return errors.New("key is nil")
	}
	return c.getCipher().DecryptStream(in, out, key)
}

func (c *VirgilCrypto) Sign(data []byte, key *ed25519PrivateKey) ([]byte, error) {
	if key == nil || key.Empty() {
		return nil, errors.New("key is nil")
	}
	return Signer.Sign(data, key)
}

func (c *VirgilCrypto) VerifySignature(data []byte, signature []byte, key *ed25519PublicKey) error {
	if key == nil || key.Empty() {
		return errors.New("key is nil")
	}
	return Verifier.Verify(data, key, signature)
}

func (c *VirgilCrypto) SignStream(in io.Reader, key *ed25519PrivateKey) ([]byte, error) {
	if key == nil || key.Empty() {
		return nil, errors.New("key is nil")
	}
	res, err := Signer.SignStream(in, key)
	if err != nil {
		return nil, err
	}
	return []byte(res), nil
}

func (c *VirgilCrypto) VerifyStream(in io.Reader, signature []byte, key *ed25519PublicKey) error {
	if key == nil || key.Empty() {
		return errors.New("key is nil")
	}
	return Verifier.VerifyStream(in, key, signature)
}

func (c *VirgilCrypto) CalculateIdentifier(data []byte) []byte {
	var hash []byte
	if c.UseSHA256Fingerprints {
		t := sha256.Sum256(data)
		hash = t[:]
	} else {
		hash = calculateNewSHA512Identifier(data)
	}
	return hash
}

func (c *VirgilCrypto) SignThenEncrypt(data []byte, signerKey *ed25519PrivateKey, recipients ...*ed25519PublicKey) ([]byte, error) {

	if signerKey == nil || signerKey.Empty() {
		return nil, errors.New("key is nil")
	}
	cipher := c.getCipher()
	for _, k := range recipients {
		if k == nil || k.Empty() {
			return nil, errors.New("key is nil")
		}
		cipher.AddKeyRecipient(k)
	}
	return cipher.SignThenEncrypt(data, signerKey)
}

func (c *VirgilCrypto) DecryptThenVerify(data []byte, decryptionKey *ed25519PrivateKey, verifierKeys ...*ed25519PublicKey) ([]byte, error) {
	if decryptionKey == nil || decryptionKey.Empty() || len(verifierKeys) == 0 {
		return nil, errors.New("key is nil")
	}

	verifiers := make([]*ed25519PublicKey, 0, len(verifierKeys))
	for _, v := range verifierKeys {
		verifiers = append(verifiers, v)
	}

	return c.getCipher().DecryptThenVerify(data, decryptionKey, verifiers...)
}

func (c *VirgilCrypto) ExtractPublicKey(key *ed25519PrivateKey) (*ed25519PublicKey, error) {
	if key == nil || key.Empty() {
		return nil, errors.New("key is nil")
	}
	return key.ExtractPublicKey()
}

func (c *VirgilCrypto) getCipher() Cipher {
	if c.MakeCipher != nil {
		return c.MakeCipher()
	}
	return NewCipher()
}

func calculateNewSHA512Identifier(data []byte) []byte {
	t := sha512.Sum512(data)
	return t[:8]
}

func calculateReceiverId(data []byte) []byte {
	return calculateNewSHA512Identifier(data)[:8]
}
