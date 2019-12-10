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
	"io/ioutil"
	"os"
	"os/user"
	"path"
	"path/filepath"

	errors "github.com/VirgilSecurity/virgil-sdk-go/errors"
)

var (
	_ Storage = &FileStorage{}
)

type FileStorage struct {
	RootDir string
}

func (s *FileStorage) Store(key string, val []byte) error {
	dir, err := s.getRootDir()
	if err != nil {
		return err
	}
	if s.Exists(key) {
		return ErrorKeyAlreadyExists
	}

	return ioutil.WriteFile(path.Join(dir, key), val, 0600)
}

func (s *FileStorage) Load(name string) ([]byte, error) {
	dir, err := s.getRootDir()
	if err != nil {
		return nil, err
	}
	if !s.Exists(name) {
		return nil, ErrorKeyNotFound
	}

	//nolint: gosec
	d, err := ioutil.ReadFile(path.Join(dir, name))
	if err != nil {
		return nil, errors.NewSDKError(err, "action", "FileStorage.Load", "file", path.Join(dir, name))
	}
	return d, nil
}

func (s *FileStorage) Exists(name string) bool {
	dir, err := s.getRootDir()
	if err != nil {
		return false
	}
	_, err = os.Stat(path.Join(dir, name))
	return !os.IsNotExist(err)
}

func (s *FileStorage) Delete(name string) error {
	dir, err := s.getRootDir()
	if err != nil {
		return err
	}
	return os.Remove(path.Join(dir, name))
}

func (s *FileStorage) getRootDir() (_ string, err error) {
	if s.RootDir == "" {
		s.RootDir, err = filepath.Abs(filepath.Dir(os.Args[0]))
		if err != nil {
			return "", errors.NewSDKError(err, "action", "FileStorage.getRootDir")
		}
		return s.RootDir, nil
	}

	s.RootDir, err = expand(s.RootDir)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(s.RootDir); os.IsNotExist(err) {
		err = os.Mkdir(s.RootDir, 0700)
		if err != nil {
			return "", err
		}
	}
	return s.RootDir, nil
}

func expand(path string) (string, error) {
	if len(path) == 0 || path[0] != '~' {
		return path, nil
	}

	usr, err := user.Current()
	if err != nil {
		return "", err
	}
	return filepath.Join(usr.HomeDir, path[1:]), nil
}
