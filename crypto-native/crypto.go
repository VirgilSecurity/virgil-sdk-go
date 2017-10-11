package cryptonative

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
	"io"

	"github.com/minio/sha256-simd"

	"gopkg.in/virgil.v6/crypto-api"
	"gopkg.in/virgil.v6/crypto-native/errors"
	"gopkg.in/virgil.v6/crypto-native/keytypes"
)

type (
	VirgilCrypto struct {
		MakeCipher func() Cipher
	}
)

var DefaultCrypto = &VirgilCrypto{}

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

func (c *VirgilCrypto) ImportPrivateKey(data []byte, password string) (cryptoapi.PrivateKey, error) {
	key, err := DecodePrivateKey(data, []byte(password))
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (c *VirgilCrypto) ImportPublicKey(data []byte) (cryptoapi.PublicKey, error) {
	key, err := DecodePublicKey(data)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (c *VirgilCrypto) ExportPrivateKey(key cryptoapi.PrivateKey, password string) ([]byte, error) {
	if ikey, ok := key.(PrivateKey); ok {
		if ikey == nil || ikey.Empty() {
			return nil, errors.New("key is nil")
		}
		return ikey.Encode([]byte(password))
	}
	return nil, cryptoapi.InsupportedKeyErr
}

func (c *VirgilCrypto) ExportPublicKey(key cryptoapi.PublicKey) ([]byte, error) {
	if ikey, ok := key.(PublicKey); ok {
		if ikey == nil || ikey.Empty() {
			return nil, errors.New("key is nil")
		}
		return ikey.Encode()
	}
	return nil, cryptoapi.InsupportedKeyErr
}

func (c *VirgilCrypto) Encrypt(data []byte, recipients ...cryptoapi.PublicKey) ([]byte, error) {
	ikeys := make([]PublicKey, len(recipients))
	for i := 0; i < len(recipients); i++ {
		var ikey PublicKey
		var ok bool
		if ikey, ok = recipients[i].(PublicKey); !ok {
			return nil, cryptoapi.InsupportedKeyErr
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

func (c *VirgilCrypto) EncryptStream(in io.Reader, out io.Writer, recipients ...cryptoapi.PublicKey) error {
	ikeys := make([]PublicKey, len(recipients))
	for i := 0; i < len(recipients); i++ {
		var ikey PublicKey
		var ok bool
		if ikey, ok = recipients[i].(PublicKey); !ok {
			return cryptoapi.InsupportedKeyErr
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

func (c *VirgilCrypto) Decrypt(data []byte, key cryptoapi.PrivateKey) ([]byte, error) {
	if ikey, ok := key.(PrivateKey); ok {
		if ikey == nil || ikey.Empty() {
			return nil, errors.New("key is nil")
		}
		return c.MakeCipher().DecryptWithPrivateKey(data, ikey.(*ed25519PrivateKey))
	}
	return nil, cryptoapi.InsupportedKeyErr
}

func (c *VirgilCrypto) DecryptStream(in io.Reader, out io.Writer, key cryptoapi.PrivateKey) error {
	if ikey, ok := key.(PrivateKey); ok {
		if ikey == nil || ikey.Empty() {
			return errors.New("key is nil")
		}
		return c.getCipher().DecryptStream(in, out, key.(*ed25519PrivateKey))
	}
	return cryptoapi.InsupportedKeyErr
}

func (c *VirgilCrypto) Sign(data []byte, key cryptoapi.PrivateKey) ([]byte, error) {
	if ikey, ok := key.(PrivateKey); ok {
		if ikey == nil || ikey.Empty() {
			return nil, errors.New("key is nil")
		}
		return Signer.Sign(data, ikey)
	}
	return nil, cryptoapi.InsupportedKeyErr
}

func (c *VirgilCrypto) VerifySignature(data []byte, signature []byte, key cryptoapi.PublicKey) error {
	if ikey, ok := key.(PublicKey); ok {
		if ikey == nil || ikey.Empty() {
			return errors.New("key is nil")
		}
		return Verifier.Verify(data, ikey, signature)
	}
	return cryptoapi.InsupportedKeyErr
}

func (c *VirgilCrypto) SignStream(in io.Reader, key cryptoapi.PrivateKey) ([]byte, error) {
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
	return nil, cryptoapi.InsupportedKeyErr
}

func (c *VirgilCrypto) VerifyStream(in io.Reader, signature []byte, key cryptoapi.PublicKey) error {
	if ikey, ok := key.(PublicKey); ok {
		if ikey == nil || ikey.Empty() {
			return errors.New("key is nil")
		}
		return Verifier.VerifyStream(in, ikey, signature)
	}
	return cryptoapi.InsupportedKeyErr
}
func (c *VirgilCrypto) CalculateFingerprint(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func (c *VirgilCrypto) SignThenEncrypt(data []byte, signerKey cryptoapi.PrivateKey, recipients ...cryptoapi.PublicKey) ([]byte, error) {
	ikeys := make([]PublicKey, len(recipients))
	for i := 0; i < len(recipients); i++ {
		var ikey PublicKey
		var ok bool
		if ikey, ok = recipients[i].(PublicKey); !ok {
			return nil, cryptoapi.InsupportedKeyErr
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
	return nil, cryptoapi.InsupportedKeyErr
}

func (c *VirgilCrypto) DecryptThenVerify(data []byte, decryptionKey cryptoapi.PrivateKey, verifierKeys ...cryptoapi.PublicKey) ([]byte, error) {
	ikeys := make([]PublicKey, len(verifierKeys))
	for i := 0; i < len(verifierKeys); i++ {
		var ikey PublicKey
		var ok bool
		if ikey, ok = verifierKeys[i].(PublicKey); !ok {
			return nil, cryptoapi.InsupportedKeyErr
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
	return nil, cryptoapi.InsupportedKeyErr
}

func (c *VirgilCrypto) ExtractPublicKey(key cryptoapi.PrivateKey) (cryptoapi.PublicKey, error) {
	if ikey, ok := key.(PrivateKey); ok {
		if ikey == nil || ikey.Empty() {
			return nil, errors.New("key is nil")
		}
		return ikey.ExtractPublicKey()
	}
	return nil, cryptoapi.InsupportedKeyErr
}

func (c *VirgilCrypto) getCipher() Cipher {
	if c.MakeCipher != nil {
		return c.MakeCipher()
	}
	return NewCipher()
}
