package cryptocgo

import (
	"io"

	"github.com/VirgilSecurity/virgil-sdk-go/crypto/cryptocgo/internal/foundation"
)

func NewEncryptWriter(w io.WriteCloser, cipher *foundation.RecipientCipher) *EncryptWriter {
	return &EncryptWriter{
		w:           w,
		cipher:      cipher,
		writeHeader: true,
	}
}

type EncryptWriter struct {
	w           io.WriteCloser
	writeHeader bool
	cipher      *foundation.RecipientCipher
}

func (sw *EncryptWriter) Write(d []byte) (int, error) {
	if sw.writeHeader {
		if _, err := sw.w.Write(sw.cipher.PackMessageInfo()); err != nil {
			return 0, err
		}
		sw.writeHeader = false
	}
	buf, err := sw.cipher.ProcessEncryption(d)
	if err != nil {
		return 0, err
	}
	if n, err := sw.w.Write(buf); err != nil {
		return n, err
	}
	return len(d), nil
}

func (sw *EncryptWriter) Close() error {
	f, err := sw.cipher.FinishEncryption()
	if err != nil {
		return err
	}
	if _, err := sw.w.Write(f); err != nil {
		return err
	}
	return sw.w.Close()
}

func NewDecryptReader(r io.Reader, cipher *foundation.RecipientCipher) *DecryptReader {
	return &DecryptReader{
		r:        r,
		cipher:   cipher,
		finished: false,
	}
}

type DecryptReader struct {
	r        io.Reader
	finished bool
	cipher   *foundation.RecipientCipher
}

func (dr *DecryptReader) Read(d []byte) (int, error) {
	var buf []byte
	n, err := dr.r.Read(d)
	if n > 0 {
		buf, err = dr.cipher.ProcessDecryption(d[:n])
		if err != nil {
			return 0, err
		}
		return copy(d, buf), nil
	}
	if err == io.EOF && !dr.finished {
		buf, err = dr.cipher.FinishDecryption()
		if err != nil {
			return 0, err
		}
		dr.finished = true
		return copy(d, buf), nil
	}
	return 0, err
}

func NopWriteCloser(w io.Writer) io.WriteCloser {
	return nopCloser{w}
}

type nopCloser struct {
	io.Writer
}

func (nopCloser) Close() error { return nil }
