package virgil

import (
	"encoding/hex"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/virgil.v4/errors"
	"gopkg.in/virgil.v4/virgilcrypto"
)

func makeRequest() (*SignableRequest, virgilcrypto.Keypair) {
	crypto := virgilcrypto.VirgilCrypto{
		Cipher: virgilcrypto.NewCipher,
	}
	kv, _ := crypto.GenerateKeypair()
	r, _ := NewRevokeCardRequest("Test", RevocationReason.Compromised)
	return r, kv
}

type FakeCrypto struct {
}

func (c *FakeCrypto) SetKeyType(keyType virgilcrypto.KeyType) error {
	return errors.New("ERROR")
}

func (c *FakeCrypto) GenerateKeypair() (virgilcrypto.Keypair, error) {
	return nil, errors.New("ERROR")
}
func (c *FakeCrypto) ImportPrivateKey(data []byte, password string) (virgilcrypto.PrivateKey, error) {
	return nil, errors.New("ERROR")
}
func (c *FakeCrypto) ImportPublicKey(data []byte) (virgilcrypto.PublicKey, error) {
	return nil, errors.New("ERROR")
}
func (c *FakeCrypto) ExportPrivateKey(key virgilcrypto.PrivateKey, password string) ([]byte, error) {
	return nil, errors.New("ERROR")
}
func (c *FakeCrypto) ExportPublicKey(key virgilcrypto.PublicKey) ([]byte, error) {
	return nil, errors.New("ERROR")
}
func (c *FakeCrypto) Encrypt(data []byte, recipients ...virgilcrypto.PublicKey) ([]byte, error) {
	return nil, errors.New("ERROR")
}
func (c *FakeCrypto) EncryptStream(in io.Reader, out io.Writer, recipients ...virgilcrypto.PublicKey) error {
	return errors.New("ERROR")
}
func (c *FakeCrypto) Decrypt(data []byte, key virgilcrypto.PrivateKey) ([]byte, error) {
	return nil, errors.New("ERROR")
}
func (c *FakeCrypto) DecryptStream(in io.Reader, out io.Writer, key virgilcrypto.PrivateKey) error {
	return errors.New("ERROR")
}
func (c *FakeCrypto) DecryptThenVerify(data []byte, privateKeyForDecryption virgilcrypto.PrivateKey, verifierKeys ...virgilcrypto.PublicKey) ([]byte, error) {
	return nil, errors.New("ERROR")
}
func (c *FakeCrypto) Sign(data []byte, signer virgilcrypto.PrivateKey) ([]byte, error) {
	return nil, errors.New("ERROR")
}
func (c *FakeCrypto) SignStream(in io.Reader, signer virgilcrypto.PrivateKey) ([]byte, error) {
	return nil, errors.New("ERROR")
}
func (c *FakeCrypto) SignThenEncrypt(data []byte, signerKey virgilcrypto.PrivateKey, recipients ...virgilcrypto.PublicKey) ([]byte, error) {
	return nil, errors.New("ERROR")
}
func (c *FakeCrypto) Verify(data []byte, signature []byte, key virgilcrypto.PublicKey) (bool, error) {
	return false, errors.New("ERROR")
}
func (c *FakeCrypto) VerifyStream(in io.Reader, signature []byte, key virgilcrypto.PublicKey) (bool, error) {
	return false, errors.New("ERROR")
}
func (c *FakeCrypto) CalculateFingerprint(data []byte) []byte {
	crypto := virgilcrypto.VirgilCrypto{
		Cipher: func() virgilcrypto.Cipher {
			return virgilcrypto.NewCipher()
		},
	}
	return crypto.CalculateFingerprint(data)
}

func (c *FakeCrypto) ExtractPublicKey(key virgilcrypto.PrivateKey) (virgilcrypto.PublicKey, error) {
	return nil, errors.New("ERROR")
}

func TestSelfSign_SignReturnErr_ReturnErr(t *testing.T) {
	r, kv := makeRequest()

	virgilcrypto.DefaultCrypto = &FakeCrypto{}

	s := RequestSigner{}
	err := s.SelfSign(r, kv.PrivateKey())

	virgilcrypto.DefaultCrypto = &virgilcrypto.VirgilCrypto{
		Cipher: virgilcrypto.NewCipher,
	}

	assert.NotNil(t, err)
}

func TestSelfSign_AddSelfSign_ReturnNil(t *testing.T) {
	r, kv := makeRequest()

	s := RequestSigner{}
	err := s.SelfSign(r, kv.PrivateKey())

	assert.Nil(t, err)

	assert.Equal(t, 1, len(r.Meta.Signatures))

	fp := Crypto().CalculateFingerprint(r.Snapshot)
	expected, _ := Crypto().Sign(fp, kv.PrivateKey())
	actual := r.Meta.Signatures[hex.EncodeToString(fp)]
	assert.Equal(t, expected, actual)
}

func TestAuthoritySign_SignReturnErr_ReturnErr(t *testing.T) {
	r, kv := makeRequest()

	virgilcrypto.DefaultCrypto = &FakeCrypto{}

	s := RequestSigner{}
	err := s.AuthoritySign(r, "test", kv.PrivateKey())

	virgilcrypto.DefaultCrypto = &virgilcrypto.VirgilCrypto{
		Cipher: virgilcrypto.NewCipher,
	}

	assert.NotNil(t, err)
}

func TestAuthoritySign_AddSelfSign_ReturnNil(t *testing.T) {
	r, kv := makeRequest()

	s := RequestSigner{}
	err := s.AuthoritySign(r, "test", kv.PrivateKey())

	assert.Nil(t, err)

	assert.Equal(t, 1, len(r.Meta.Signatures))

	fp := Crypto().CalculateFingerprint(r.Snapshot)
	expected, _ := Crypto().Sign(fp, kv.PrivateKey())
	actual := r.Meta.Signatures["test"]
	assert.Equal(t, expected, actual)
}
