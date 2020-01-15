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

package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"

	verrors "github.com/VirgilSecurity/virgil-sdk-go/v6/errors"
)

const (
	//
	// KeyLength is the exact key length accepted by NewSymmetricEncryptStorage
	//
	KeyLength = 32

	symSaltLen  = 32
	symNonceLen = 12
	symTagLen   = 16
)

var (
	encryptInfo = []byte("VIRGILSYMMETRICENCRYPTSTORAGE")

	ErrEncryptedDataInvalid = errors.New("encrypt data invalid")

	_ Storage = &SymmetricEncryptStorage{}
)

func NewSymmetricEncryptStorage(key [KeyLength]byte, storage Storage) *SymmetricEncryptStorage {
	if storage == nil {
		panic("NewSymmetricEncryptStorage: storage is nil")
	}
	return &SymmetricEncryptStorage{
		key:     key[:],
		storage: storage,
	}
}

type SymmetricEncryptStorage struct {
	key     []byte
	storage Storage
}

func (s *SymmetricEncryptStorage) Store(key string, val []byte) error {
	salt := make([]byte, symSaltLen)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return verrors.NewSDKError(err, "action", "SymmetricEncryptStorage.Store")
	}

	kdf := hkdf.New(sha512.New, s.key, salt, encryptInfo)

	keyNonce := make([]byte, KeyLength+symNonceLen)
	_, err = kdf.Read(keyNonce)
	if err != nil {
		return err
	}

	aesgcm, err := aes.NewCipher(keyNonce[:KeyLength])
	if err != nil {
		return err
	}

	aesGcm, err := cipher.NewGCM(aesgcm)
	if err != nil {
		return err
	}

	ct := make([]byte, symSaltLen+len(val)+aesGcm.Overhead())
	copy(ct, salt)

	aesGcm.Seal(ct[:symSaltLen], keyNonce[KeyLength:], val, nil)
	return s.Store(key, ct)
}

func (s *SymmetricEncryptStorage) Load(key string) ([]byte, error) {
	data, err := s.storage.Load(key)
	if err != nil {
		return nil, err
	}
	if len(data) < (symSaltLen + symTagLen) {
		return nil, verrors.NewSDKError(ErrEncryptedDataInvalid, "action", "SymmetricEncryptStorage.Load", "key", key)
	}

	salt := data[:symSaltLen]
	kdf := hkdf.New(sha512.New, s.key, salt, encryptInfo)

	keyNonce := make([]byte, KeyLength+symNonceLen)

	if _, err = kdf.Read(keyNonce); err != nil {
		return nil, err
	}

	aesgcm, err := aes.NewCipher(keyNonce[:KeyLength])
	if err != nil {
		return nil, err
	}

	aesGcm, err := cipher.NewGCM(aesgcm)
	if err != nil {
		return nil, err
	}

	dst := make([]byte, 0)
	return aesGcm.Open(dst, keyNonce[KeyLength:], data[symSaltLen:], nil)
}

func (s *SymmetricEncryptStorage) Exists(key string) bool {
	return s.storage.Exists(key)
}
func (s *SymmetricEncryptStorage) Delete(key string) error {
	return s.storage.Delete(key)
}
