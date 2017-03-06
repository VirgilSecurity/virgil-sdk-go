package virgilcrypto

/*
Copyright (C) 2016-2017 Virgil Security Inc.

Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>

All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

  (1) Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  (2) Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in
  the documentation and/or other materials provided with the
  distribution.

  (3) Neither the name of the copyright holder nor the names of its
  contributors may be used to endorse or promote products derived
  from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/
import (
	"crypto/sha256"
	"io"

	"gopkg.in/virgil.v4/errors"
	"gopkg.in/virgil.v4/virgilcrypto/keytypes"
)

type (
	Crypto interface {
		SetKeyType(keyType KeyType) error
		GenerateKeypair() (Keypair, error)
		ImportPrivateKey(data []byte, password string) (PrivateKey, error)
		ImportPublicKey(data []byte) (PublicKey, error)
		ExportPrivateKey(key PrivateKey, password string) ([]byte, error)
		ExportPublicKey(key PublicKey) ([]byte, error)
		Encrypt(data []byte, recipients ...PublicKey) ([]byte, error)
		EncryptStream(in io.Reader, out io.Writer, recipients ...PublicKey) error
		Decrypt(data []byte, key PrivateKey) ([]byte, error)
		DecryptStream(in io.Reader, out io.Writer, key PrivateKey) error
		DecryptThenVerify(data []byte, privateKeyForDecryption PrivateKey, verifierKey PublicKey) ([]byte, error)
		Sign(data []byte, signer PrivateKey) ([]byte, error)
		SignStream(in io.Reader, signer PrivateKey) ([]byte, error)
		SignThenEncrypt(data []byte, signerKey PrivateKey, recipients ...PublicKey) ([]byte, error)
		//Verify must return non nil error if the result is false
		Verify(data []byte, signature []byte, key PublicKey) (bool, error)
		VerifyStream(in io.Reader, signature []byte, key PublicKey) (bool, error)
		CalculateFingerprint(data []byte) []byte
		ExtractPublicKey(key PrivateKey) (PublicKey, error)
	}

	VirgilCrypto struct {
		Cipher func() Cipher
	}
)

var DefaultCrypto Crypto

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
	if key == nil || key.Empty() {
		return nil, errors.New("key is nil")
	}
	return key.Encode([]byte(password))
}

func (c *VirgilCrypto) ExportPublicKey(key PublicKey) ([]byte, error) {
	if key == nil || key.Empty() {
		return nil, errors.New("key is nil")
	}
	return key.Encode()
}

func (c *VirgilCrypto) Encrypt(data []byte, recipients ...PublicKey) ([]byte, error) {
	cipher := c.Cipher()
	for _, k := range recipients {
		if k == nil || k.Empty() {
			return nil, errors.New("key is nil")
		}
		cipher.AddKeyRecipient(k.(*ed25519PublicKey))
	}
	return cipher.Encrypt(data)
}

func (c *VirgilCrypto) EncryptStream(in io.Reader, out io.Writer, recipients ...PublicKey) error {
	cipher := c.Cipher()
	for _, k := range recipients {
		if k == nil || k.Empty() {
			return errors.New("key is nil")
		}
		cipher.AddKeyRecipient(k.(*ed25519PublicKey))
	}
	return cipher.EncryptStream(in, out)
}

func (c *VirgilCrypto) Decrypt(data []byte, key PrivateKey) ([]byte, error) {
	if key == nil || key.Empty() {
		return nil, errors.New("key is nil")
	}
	return c.Cipher().DecryptWithPrivateKey(data, key.(*ed25519PrivateKey))
}

func (c *VirgilCrypto) DecryptStream(in io.Reader, out io.Writer, key PrivateKey) error {
	if key == nil || key.Empty() {
		return errors.New("key is nil")
	}
	return c.Cipher().DecryptStream(in, out, key.(*ed25519PrivateKey))
}

func (c *VirgilCrypto) Sign(data []byte, signer PrivateKey) ([]byte, error) {
	if signer == nil || signer.Empty() {
		return nil, errors.New("key is nil")
	}
	return Signer.Sign(data, signer)
}

func (c *VirgilCrypto) Verify(data []byte, signature []byte, key PublicKey) (bool, error) {
	if key == nil || key.Empty() {
		return false, errors.New("key is nil")
	}
	return Verifier.Verify(data, key, signature)
}

func (c *VirgilCrypto) SignStream(in io.Reader, signer PrivateKey) ([]byte, error) {
	if signer == nil || signer.Empty() {
		return nil, errors.New("key is nil")
	}
	res, err := Signer.SignStream(in, signer)
	if err != nil {
		return nil, err
	}
	return []byte(res), nil
}

func (c *VirgilCrypto) VerifyStream(in io.Reader, signature []byte, key PublicKey) (bool, error) {
	if key == nil || key.Empty() {
		return false, errors.New("key is nil")
	}
	return Verifier.VerifyStream(in, key, signature)
}
func (c *VirgilCrypto) CalculateFingerprint(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func (c *VirgilCrypto) SignThenEncrypt(data []byte, signerKey PrivateKey, recipients ...PublicKey) ([]byte, error) {
	if signerKey == nil || signerKey.Empty() {
		return nil, errors.New("key is nil")
	}
	cipher := c.Cipher()
	for _, k := range recipients {
		if k == nil || k.Empty() {
			return nil, errors.New("key is nil")
		}
		cipher.AddKeyRecipient(k.(*ed25519PublicKey))
	}
	return cipher.SignThenEncrypt(data, signerKey.(*ed25519PrivateKey))
}

func (c *VirgilCrypto) DecryptThenVerify(data []byte, decryptionKey PrivateKey, verifierKey PublicKey) ([]byte, error) {

	if decryptionKey == nil || decryptionKey.Empty() || verifierKey == nil || verifierKey.Empty() {
		return nil, errors.New("key is nil")
	}
	return c.Cipher().DecryptThenVerify(data, decryptionKey.(*ed25519PrivateKey), verifierKey.(*ed25519PublicKey))
}

func (c *VirgilCrypto) ExtractPublicKey(key PrivateKey) (PublicKey, error) {
	if key == nil || key.Empty() {
		return nil, errors.New("key is nil")
	}
	return key.ExtractPublicKey()
}

func init() {
	DefaultCrypto = &VirgilCrypto{
		Cipher: func() Cipher {
			return NewCipher()
		},
	}
}
