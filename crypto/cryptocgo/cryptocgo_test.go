package cryptocgo_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/VirgilSecurity/virgil-sdk-go/crypto"
	"github.com/VirgilSecurity/virgil-sdk-go/crypto/cryptocgo"
)

func TestSignVerify(t *testing.T) {
	crypto := cryptocgo.NewVirgilCrypto()

	//make random data
	data := make([]byte, 257)
	rand.Read(data)

	signerKey, err := crypto.GenerateKeypair()
	require.NoError(t, err)

	sign, err := crypto.Sign(data, signerKey)
	require.NoError(t, err)

	err = crypto.VerifySignature(data, sign, signerKey.PublicKey())
	assert.NoError(t, err)
}

func TestEncryptDecrypt(t *testing.T) {
	crypto := cryptocgo.NewVirgilCrypto()

	//make random data
	data := make([]byte, 257)
	rand.Read(data)

	encryptKey, err := crypto.GenerateKeypair()
	require.NoError(t, err)

	cipherText, err := crypto.Encrypt(data, encryptKey.PublicKey())
	require.NoError(t, err)

	actualData, err := crypto.Decrypt(cipherText, encryptKey)
	assert.NoError(t, err)
	assert.Equal(t, data, actualData)
}

func TestStreamCipher(t *testing.T) {
	crypto := cryptocgo.NewVirgilCrypto()
	key, err := crypto.GenerateKeypair()
	require.NoError(t, err)

	plainBuf := make([]byte, 102301)
	rand.Read(plainBuf)

	plain := bytes.NewReader(plainBuf)
	cipheredStream := bytes.NewBuffer(nil)
	err = crypto.EncryptStream(plain, cipheredStream, key.PublicKey())
	require.NoError(t, err)

	t.Logf("encrypted data: %s", base64.StdEncoding.EncodeToString(cipheredStream.Bytes()))

	//decrypt with key
	cipheredInputStream := bytes.NewReader(cipheredStream.Bytes())
	plainOutBuffer := bytes.NewBuffer(nil)
	err = crypto.DecryptStream(cipheredInputStream, plainOutBuffer, key)
	assert.NoError(t, err, "decrypt with correct key")
	assert.Equal(t, plainBuf, plainOutBuffer.Bytes(), "decrypt with correct key: plain & decrypted buffers do not match")

	//decrypt with wrong id must fail
	wrongKey, err := crypto.GenerateKeypair()
	require.NoError(t, err)

	cipheredInputStream = bytes.NewReader(cipheredStream.Bytes())
	plainOutBuffer = bytes.NewBuffer(nil)

	err = crypto.DecryptStream(cipheredInputStream, plainOutBuffer, wrongKey)
	assert.Error(t, err, "decrypt with incorrect key")
}

func TestStreamSigner(t *testing.T) {
	crypto := cryptocgo.NewVirgilCrypto()
	key, err := crypto.GenerateKeypair()
	require.NoError(t, err)

	plainBuf := make([]byte, 1023)
	rand.Read(plainBuf)
	plain := bytes.NewBuffer(plainBuf)
	sign, err := crypto.SignStream(plain, key)
	require.NoError(t, err)

	//verify signature
	plain = bytes.NewBuffer(plainBuf)
	err = crypto.VerifyStream(plain, sign, key.PublicKey())
	assert.NoError(t, err)

	//verify with wrong key must fail
	wrongKey, err := crypto.GenerateKeypair()
	require.NoError(t, err)

	err = crypto.VerifyStream(plain, sign, wrongKey.PublicKey())
	assert.Error(t, cryptocgo.ErrSignVerification, err)

	//verify with wrong signature must fail
	plain = bytes.NewBuffer(plainBuf)
	sign[len(sign)-1] = ^sign[len(sign)-1] //invert last byte

	err = crypto.VerifyStream(plain, sign, wrongKey.PublicKey())
	assert.Equal(t, cryptocgo.ErrSignVerification, err)
}

func TestExportImportKeys(t *testing.T) {
	crypto := cryptocgo.NewVirgilCrypto()
	key, err := crypto.GenerateKeypair()
	require.NoError(t, err)

	pubb, err := crypto.ExportPublicKey(key.PublicKey())
	assert.NoError(t, err)

	privb, err := crypto.ExportPrivateKey(key)
	assert.NoError(t, err)

	pub, err := crypto.ImportPublicKey(pubb)
	assert.NoError(t, err)

	priv, err := crypto.ImportPrivateKey(privb)
	assert.NoError(t, err)

	data := make([]byte, 257)
	rand.Read(data)

	// check that import keys was correct
	{
		cipherText, err := crypto.SignThenEncrypt(data, key, key.PublicKey())
		require.NoError(t, err)

		plaintext, err := crypto.DecryptThenVerify(cipherText, priv, pub)
		require.NoError(t, err)
		require.Equal(t, plaintext, data)
	}
}

func TestSignAndEncryptAndDecryptAndVerify(t *testing.T) {
	crypto := cryptocgo.NewVirgilCrypto()

	signKey, err := crypto.GenerateKeypair()
	require.NoError(t, err)

	encryptKey, err := crypto.GenerateKeypair()
	require.NoError(t, err)

	data := make([]byte, 257)
	rand.Read(data)

	cipherText, err := crypto.SignAndEncrypt(data, signKey, encryptKey.PublicKey())
	require.NoError(t, err)

	plaintext, err := crypto.DecryptAndVerify(cipherText, encryptKey, signKey.PublicKey(), encryptKey.PublicKey())
	require.NoError(t, err)
	require.Equal(t, data, plaintext)
}

func TestSignThenEncryptAndDecryptThenVerify(t *testing.T) {
	crypto := cryptocgo.NewVirgilCrypto()

	signKey, err := crypto.GenerateKeypair()
	require.NoError(t, err)

	encryptKey, err := crypto.GenerateKeypair()
	require.NoError(t, err)

	data := make([]byte, 257)
	rand.Read(data)

	cipherText, err := crypto.SignThenEncrypt(data, signKey, encryptKey.PublicKey())
	require.NoError(t, err)

	plaintext, err := crypto.DecryptThenVerify(cipherText, encryptKey, signKey.PublicKey(), encryptKey.PublicKey())
	require.NoError(t, err)
	require.Equal(t, data, plaintext)
}

func TestGenerateKeypairFromKeyMaterial(t *testing.T) {
	seed := make([]byte, 384)
	for i := range seed {
		seed[i] = byte(i)
	}

	pub1, priv1 := GenKeysFromSeed(t, seed)

	for i := 0; i < 10; i++ {
		pub2, priv2 := GenKeysFromSeed(t, seed)
		require.Equal(t, pub1, pub2)
		require.Equal(t, priv1, priv2)
	}

	// check if we change seed than key pair is different
	{
		seed[383]++
		pub3, priv3 := GenKeysFromSeed(t, seed)
		require.NotEqual(t, pub1, pub3)
		require.NotEqual(t, priv1, priv3)
	}
}

func GenKeysFromSeed(t *testing.T, seed []byte) (publicKey []byte, privateKey []byte) {
	crypto := cryptocgo.NewVirgilCrypto()
	key, err := crypto.GenerateKeypairFromKeyMaterial(seed)
	require.NoError(t, err)

	publicKey, err = crypto.ExportPublicKey(key.PublicKey())
	require.NoError(t, err)

	privateKey, err = crypto.ExportPrivateKey(key)
	require.NoError(t, err)

	return publicKey, privateKey
}

func TestGenerateKeypairFromKeyMaterialBadCase(t *testing.T) {
	table := []struct {
		name string
		size int
	}{
		{"less 32", 31},
		{"greater 512", 513},
	}
	vcrypto := cryptocgo.NewVirgilCrypto()

	for _, test := range table {
		data, err := vcrypto.Random(test.size)
		require.NoError(t, err)

		_, err = vcrypto.GenerateKeypairFromKeyMaterial(data)
		assert.Equal(t, cryptocgo.ErrInvalidSeedSize, err, test.name)
	}
}

func TestKeyTypes(t *testing.T) {
	vcrypto := cryptocgo.NewVirgilCrypto()
	m, err := vcrypto.Random(128)
	require.NoError(t, err)

	table := []struct {
		kt            crypto.KeyType
		expectedError error
	}{
		{crypto.Default, nil},
		{crypto.RSA_2048, nil},
		// {crypto.RSA_3072, nil},
		// {crypto.RSA_4096, nil},
		// {crypto.RSA_8192, nil},
		{crypto.EC_SECP256R1, nil},
		{crypto.EC_CURVE25519, nil},
		{crypto.FAST_EC_ED25519, nil},
		{crypto.KeyType(100), cryptocgo.ErrUnsupportedKeyType},
	}

	fs := []func(kt crypto.KeyType) error{
		vcrypto.SetKeyType,
		func(kt crypto.KeyType) error {
			_, err := vcrypto.GenerateKeypairForType(kt)
			return err
		},
		func(kt crypto.KeyType) error {
			_, err := vcrypto.GenerateKeypairFromKeyMaterialForType(kt, m)
			return err
		},
	}
	for _, test := range table {
		for _, f := range fs {
			err := f(test.kt)
			assert.Equal(t, test.expectedError, err, test.kt)
		}
	}
}
