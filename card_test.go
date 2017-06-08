package virgil

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"gopkg.in/virgil.v4/virgilcrypto"
)

func makeFakeCard() (*Card, virgilcrypto.Keypair) {
	kv, _ := Crypto().GenerateKeypair()
	return &Card{
		PublicKey: kv.PublicKey(),
	}, kv
}

func TestEncrypt_ReturnCorrectData(t *testing.T) {
	c, kv := makeFakeCard()
	plainText := []byte(`Test data`)
	cipherText, _ := c.Encrypt(plainText)
	actual, _ := Crypto().Decrypt(cipherText, kv.PrivateKey())

	assert.Equal(t, plainText, actual)
}

func TestSignThenEncrypt_ReturnCorrectData(t *testing.T) {
	c, kv := makeFakeCard()
	plainText := []byte(`Test data`)
	cipherText, _ := c.SignThenEncrypt(plainText, kv.PrivateKey())
	actual, _ := Crypto().DecryptThenVerify(cipherText, kv.PrivateKey(), kv.PublicKey())

	assert.Equal(t, plainText, actual)
}

func TestVerify_ReturnCorrectData(t *testing.T) {
	c, kv := makeFakeCard()
	data := []byte(`Test data`)
	sign, _ := Crypto().Sign(data, kv.PrivateKey())
	err := c.Verify(data, sign)

	assert.NoError(t, err)
}
