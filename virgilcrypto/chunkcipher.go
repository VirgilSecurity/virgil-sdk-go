package virgilcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"io"

	"gopkg.in/virgil.v4/virgilcrypto/gcm"
)

type VirgilChunkCipher interface {
	Encrypt(key, nonce, ad []byte, chunkSize int, in io.Reader, out io.Writer) error
	Decrypt(key, nonce, ad []byte, chunkSize int, in io.Reader, out io.Writer) error
}

var DefaultChunkSize = 1024 * 1024

type aesGCMChunkStreamCipher struct{}

const (
	gcmTagSize = 16
)

func (c *aesGCMChunkStreamCipher) Encrypt(key, nonce, ad []byte, chunkSize int, in io.Reader, out io.Writer) error {

	if chunkSize < 1 {
		return CryptoError("chunk size too small")
	}

	buf := make([]byte, chunkSize+gcmTagSize)

	var counter = make([]byte, len(nonce))
	var chunkNonce = make([]byte, len(nonce))

	n, err := in.Read(buf[:chunkSize])
	for n > 0 && err == nil {
		gcm.XorBytes(chunkNonce, nonce, counter)
		ciph, _ := aes.NewCipher(key)
		aesGCM, _ := cipher.NewGCM(ciph)

		res := aesGCM.Seal(buf[:0], chunkNonce, buf[:n], ad)

		written, err := out.Write(res)
		if written != len(res) || err != nil {
			return CryptoError("Could not write to output buffer")
		}

		increment(counter)
		n, err = in.Read(buf[:chunkSize])
	}

	if err != nil && err != io.EOF {
		return err
	}
	return nil
}
func (c *aesGCMChunkStreamCipher) Decrypt(key, nonce, ad []byte, chunkSize int, in io.Reader, out io.Writer) error {
	if chunkSize < 1 {
		return CryptoError("chunk size too small")
	}

	buf := make([]byte, chunkSize+gcmTagSize)

	var counter = make([]byte, len(nonce))
	var chunkNonce = make([]byte, len(nonce))

	n, err := in.Read(buf)
	for n > 0 && err == nil {
		gcm.XorBytes(chunkNonce, nonce, counter)
		ciph, _ := aes.NewCipher(key)
		aesGCM, _ := cipher.NewGCM(ciph)

		res, err := aesGCM.Open(buf[:0], chunkNonce, buf[:n], ad)
		if err != nil {
			return err
		}
		written, err := out.Write(res)
		if written != len(res) || err != nil {
			return CryptoError("Could not write to output buffer")
		}
		increment(counter)
		n, err = in.Read(buf)
	}

	if err != nil && err != io.EOF {
		return err
	}
	return nil
}

func increment(counter []byte) {
	for i := len(counter) - 1; i >= 0; i-- {
		counter[i]++
		if counter[i] != 0 {
			break
		}
	}
}
