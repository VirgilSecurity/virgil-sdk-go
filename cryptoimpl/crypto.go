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

func (c *VirgilCrypto) GenerateKeypair() (Keypair, error) {

	keypair, err := NewKeypair()
	return keypair, err
}

func (c *VirgilCrypto) ImportPrivateKey(data []byte, password string) (PrivateKey, error) {
	key, err := DecodePrivateKey(data, []byte(password))
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (c *VirgilCrypto) ImportPublicKey(data []byte) (PublicKey, error) {
	key, err := DecodePublicKey(data)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (c *VirgilCrypto) ExportPrivateKey(key PrivateKey, password string) ([]byte, error) {
	if ikey, ok := key.(PrivateKey); ok {
		if ikey == nil || ikey.Empty() {
			return nil, errors.New("key is nil")
		}
		return ikey.Encode([]byte(password))
	}
	return nil, UnsupportedKeyErr
}

func (c *VirgilCrypto) ExportPublicKey(key PublicKey) ([]byte, error) {
	if ikey, ok := key.(PublicKey); ok {
		if ikey == nil || ikey.Empty() {
			return nil, errors.New("key is nil")
		}
		return ikey.Encode()
	}
	return nil, UnsupportedKeyErr
}

func (c *VirgilCrypto) Encrypt(data []byte, recipients ...PublicKey) ([]byte, error) {
	ikeys := make([]PublicKey, len(recipients))
	for i := 0; i < len(recipients); i++ {
		var ikey PublicKey
		var ok bool
		if ikey, ok = recipients[i].(PublicKey); !ok {
			return nil, UnsupportedKeyErr
		}
		ikeys[i] = ikey
	}
	cipher := c.getCipher()
	for _, k := range ikeys {
		if k == nil || k.Empty() {
			return nil, errors.New("key is nil")
		}
		cipher.AddKeyRecipient(k.(*ed25519PublicKey))
	}
	return cipher.Encrypt(data)
}

func (c *VirgilCrypto) EncryptStream(in io.Reader, out io.Writer, recipients ...PublicKey) error {
	ikeys := make([]PublicKey, len(recipients))
	for i := 0; i < len(recipients); i++ {
		var ikey PublicKey
		var ok bool
		if ikey, ok = recipients[i].(PublicKey); !ok {
			return UnsupportedKeyErr
		}
		ikeys[i] = ikey
	}

	cipher := c.getCipher()
	for _, k := range ikeys {
		if k == nil || k.Empty() {
			return errors.New("key is nil")
		}
		cipher.AddKeyRecipient(k.(*ed25519PublicKey))
	}
	return cipher.EncryptStream(in, out)
}

func (c *VirgilCrypto) Decrypt(data []byte, key PrivateKey) ([]byte, error) {
	if ikey, ok := key.(PrivateKey); ok {
		if ikey == nil || ikey.Empty() {
			return nil, errors.New("key is nil")
		}
		return c.MakeCipher().DecryptWithPrivateKey(data, ikey.(*ed25519PrivateKey))
	}
	return nil, UnsupportedKeyErr
}

func (c *VirgilCrypto) DecryptStream(in io.Reader, out io.Writer, key PrivateKey) error {
	if ikey, ok := key.(PrivateKey); ok {
		if ikey == nil || ikey.Empty() {
			return errors.New("key is nil")
		}
		return c.getCipher().DecryptStream(in, out, key.(*ed25519PrivateKey))
	}
	return UnsupportedKeyErr
}

func (c *VirgilCrypto) Sign(data []byte, key PrivateKey) ([]byte, error) {
	if ikey, ok := key.(PrivateKey); ok {
		if ikey == nil || ikey.Empty() {
			return nil, errors.New("key is nil")
		}
		return Signer.Sign(data, ikey)
	}
	return nil, UnsupportedKeyErr
}

func (c *VirgilCrypto) VerifySignature(data []byte, signature []byte, key PublicKey) error {
	if ikey, ok := key.(PublicKey); ok {
		if ikey == nil || ikey.Empty() {
			return errors.New("key is nil")
		}
		return Verifier.Verify(data, ikey, signature)
	}
	return UnsupportedKeyErr
}

func (c *VirgilCrypto) SignStream(in io.Reader, key PrivateKey) ([]byte, error) {
	if ikey, ok := key.(PrivateKey); ok {
		if ikey == nil || ikey.Empty() {
			return nil, errors.New("key is nil")
		}
		res, err := Signer.SignStream(in, ikey)
		if err != nil {
			return nil, err
		}
		return []byte(res), nil
	}
	return nil, UnsupportedKeyErr
}

func (c *VirgilCrypto) VerifyStream(in io.Reader, signature []byte, key PublicKey) error {
	if ikey, ok := key.(PublicKey); ok {
		if ikey == nil || ikey.Empty() {
			return errors.New("key is nil")
		}
		return Verifier.VerifyStream(in, ikey, signature)
	}
	return UnsupportedKeyErr
}

/*func (c *VirgilCrypto) GenerateHash(data []byte) []byte {
	var hash []byte
	if c.UseSHA256Fingerprints {
		t := sha256.Sum256(data)
		hash = t[:]
	} else {
		t := sha512.Sum512(data)
		hash = t[:32]
	}
	return hash
}*/

func (c *VirgilCrypto) CalculateReceiverId(data []byte) []byte {
	var hash []byte
	if c.UseSHA256Fingerprints {
		t := sha256.Sum256(data)
		hash = t[:]
	} else {
		t := sha512.Sum512(data)
		hash = t[:8]
	}
	return hash
}

func (c *VirgilCrypto) SignThenEncrypt(data []byte, signerKey PrivateKey, recipients ...PublicKey) ([]byte, error) {
	ikeys := make([]PublicKey, len(recipients))
	for i := 0; i < len(recipients); i++ {
		var ikey PublicKey
		var ok bool
		if ikey, ok = recipients[i].(PublicKey); !ok {
			return nil, UnsupportedKeyErr
		}
		ikeys[i] = ikey
	}

	if iSignerKey, ok := signerKey.(PrivateKey); ok {
		if iSignerKey == nil || iSignerKey.Empty() {
			return nil, errors.New("key is nil")
		}
		cipher := c.getCipher()
		for _, k := range ikeys {
			if k == nil || k.Empty() {
				return nil, errors.New("key is nil")
			}
			cipher.AddKeyRecipient(k.(*ed25519PublicKey))
		}
		return cipher.SignThenEncrypt(data, iSignerKey.(*ed25519PrivateKey))
	}
	return nil, UnsupportedKeyErr
}

func (c *VirgilCrypto) DecryptThenVerify(data []byte, decryptionKey PrivateKey, verifierKeys ...PublicKey) ([]byte, error) {
	ikeys := make([]PublicKey, len(verifierKeys))
	for i := 0; i < len(verifierKeys); i++ {
		var ikey PublicKey
		var ok bool
		if ikey, ok = verifierKeys[i].(PublicKey); !ok {
			return nil, UnsupportedKeyErr
		}
		ikeys[i] = ikey
	}

	if iDecryptkey, ok := decryptionKey.(PrivateKey); ok {
		if iDecryptkey == nil || iDecryptkey.Empty() || len(ikeys) == 0 {
			return nil, errors.New("key is nil")
		}

		verifiers := make([]*ed25519PublicKey, 0, len(ikeys))
		for _, v := range ikeys {
			verifiers = append(verifiers, v.(*ed25519PublicKey))
		}

		return c.getCipher().DecryptThenVerify(data, iDecryptkey.(*ed25519PrivateKey), verifiers...)
	}
	return nil, UnsupportedKeyErr
}

func (c *VirgilCrypto) ExtractPublicKey(key PrivateKey) (PublicKey, error) {
	if ikey, ok := key.(PrivateKey); ok {
		if ikey == nil || ikey.Empty() {
			return nil, errors.New("key is nil")
		}
		return ikey.ExtractPublicKey()
	}
	return nil, UnsupportedKeyErr
}

func (c *VirgilCrypto) getCipher() Cipher {
	if c.MakeCipher != nil {
		return c.MakeCipher()
	}
	return NewCipher()
}
