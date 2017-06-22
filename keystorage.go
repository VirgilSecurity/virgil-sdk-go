package virgil

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"

	"gopkg.in/virgil.v5/errors"
)

type KeyStorage interface {
	Store(key *StorageItem) error
	Load(name string) (*StorageItem, error)
	Exists(name string) bool
	Delete(name string) error
}

type StorageItem struct {
	Name string
	Data []byte
	Meta map[string]string
}

var (
	ErrorKeyAlreadyExists = errors.New("Key already exists")
	ErrorKeyNotFound      = errors.New("Key not found")
)

type storageKeyJSON struct {
	Data []byte
	Meta map[string]string
}
type FileStorage struct {
	RootDir string
}

func (s *FileStorage) Store(key *StorageItem) error {
	dir, err := s.getRootDir()
	if err != nil {
		return err
	}
	if s.Exists(key.Name) {
		return ErrorKeyAlreadyExists
	}

	data, err := json.Marshal(storageKeyJSON{
		Data: key.Data,
		Meta: key.Meta,
	})
	if err != nil {
		return errors.Wrap(err, "FileStorage cannot marshal data")
	}

	ioutil.WriteFile(path.Join(dir, key.Name), data, 400)
	return nil
}

func (s *FileStorage) Load(name string) (*StorageItem, error) {
	dir, err := s.getRootDir()
	if err != nil {
		return nil, err
	}
	if !s.Exists(name) {
		return nil, ErrorKeyNotFound
	}
	d, err := ioutil.ReadFile(path.Join(dir, name))
	if err != nil {
		return nil, errors.Wrap(err, "Cannot read file")
	}
	j := new(storageKeyJSON)
	err = json.Unmarshal(d, j)
	if err != nil {
		return nil, errors.Wrap(err, "FileStorage cannot unmarshal data")
	}
	return &StorageItem{
		Name: name,
		Data: j.Data,
		Meta: j.Meta,
	}, nil
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

func (s *FileStorage) getRootDir() (string, error) {
	if s.RootDir == "" {
		var err error
		s.RootDir, err = filepath.Abs(filepath.Dir(os.Args[0]))
		if err != nil {
			return "", errors.Wrap(err, "FileStorage cannot get executable path")
		}
	}
	return s.RootDir, nil
}
