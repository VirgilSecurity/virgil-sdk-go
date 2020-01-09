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
	"encoding/json"
	"errors"

	"github.com/VirgilSecurity/virgil-sdk-go/crypto"
	verrors "github.com/VirgilSecurity/virgil-sdk-go/errors"
)

var (
	// DefaultPrivateKeyExporter is private key exporter is used by default
	DefaultPrivateKeyExporter PrivateKeyExporter = &crypto.Crypto{}
)

type PrivateKeyExporter interface {
	ExportPrivateKey(privateKey crypto.PrivateKey) ([]byte, error)
	ImportPrivateKey(data []byte) (privateKey crypto.PrivateKey, err error)
}
type storageKeyJSON struct {
	Key  []byte            `json:"key"`
	Meta map[string]string `json:"meta"`
}

type PrivateKeyExporterOption func(s *VirgilPrivateKeyStorage)

func SetPrivateKeyStorageExporter(e PrivateKeyExporter) PrivateKeyExporterOption {
	return func(s *VirgilPrivateKeyStorage) {
		s.privateKeyExporter = e
	}
}

type VirgilPrivateKeyStorage struct {
	privateKeyExporter PrivateKeyExporter
	storage            Storage
}

func NewVirgilPrivateKeyStorage(storage Storage, options ...PrivateKeyExporterOption) *VirgilPrivateKeyStorage {
	pks := &VirgilPrivateKeyStorage{
		privateKeyExporter: DefaultPrivateKeyExporter,
		storage:            storage,
	}
	for _, o := range options {
		o(pks)
	}
	if err := pks.Validate(); err != nil {
		panic(err)
	}
	return pks
}

func (v *VirgilPrivateKeyStorage) Validate() error {
	if v.privateKeyExporter == nil {
		return errors.New("VirgilPrivateKeyStorage: private key exporter is not set")
	}

	if v.storage == nil {
		return errors.New("VirgilPrivateKeyStorage: key storage is not set")
	}
	return nil
}

func (v *VirgilPrivateKeyStorage) Store(privateKey crypto.PrivateKey, name string, meta map[string]string) error {
	exported, err := v.privateKeyExporter.ExportPrivateKey(privateKey)
	if err != nil {
		return verrors.NewSDKError(err, "action", "VirgilPrivateKeyStorage.Store")
	}

	data, err := json.Marshal(storageKeyJSON{Key: exported, Meta: meta})
	if err != nil {
		return verrors.NewSDKError(err, "action", "VirgilPrivateKeyStorage.Store")
	}
	return v.storage.Store(name, data)
}

func (v *VirgilPrivateKeyStorage) Load(name string) (privateKey crypto.PrivateKey, meta map[string]string, err error) {
	data, err := v.storage.Load(name)
	if err != nil {
		return nil, nil, verrors.NewSDKError(err, "action", "VirgilPrivateKeyStorage.Load", "name", name)
	}
	var j storageKeyJSON
	if err = json.Unmarshal(data, &j); err != nil {
		return nil, nil, verrors.NewSDKError(err, "action", "VirgilPrivateKeyStorage.Load", "name", name)
	}

	privateKey, err = v.privateKeyExporter.ImportPrivateKey(j.Key)
	if err != nil {
		return nil, nil, verrors.NewSDKError(err, "action", "VirgilPrivateKeyStorage.Load", "name", name)
	}

	return privateKey, j.Meta, nil
}

func (v *VirgilPrivateKeyStorage) Delete(name string) error {
	return v.storage.Delete(name)
}
