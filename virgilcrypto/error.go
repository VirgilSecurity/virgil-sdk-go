package virgilcrypto

import "gopkg.in/virgil.v5/errors"

type CryptoError string

func (c CryptoError) Error() string {
	return string(c)
}

type WrongPasswordError struct {
	CryptoError
}

func cryptoError(err error, msg string) error {
	if err == nil {
		return nil
	}
	return errors.Wrap(CryptoError(err.Error()), msg)
}
