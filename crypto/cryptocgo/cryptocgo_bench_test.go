package cryptocgo_test

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/VirgilSecurity/virgil-sdk-go/crypto/cryptocgo"
)

func BenchmarkSign(b *testing.B) {
	crypto := cryptocgo.NewVirgilCrypto()

	//make random data
	data := make([]byte, 257)
	rand.Read(data)

	signerKeypair, err := crypto.GenerateKeypair()
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err = crypto.Sign(data, signerKeypair)
		if err != nil {
			b.Fatalf("Sing return error: %v", err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	crypto := cryptocgo.NewVirgilCrypto()

	//make random data
	data := make([]byte, 257)
	rand.Read(data)

	signerSk, err := crypto.GenerateKeypair()
	require.NoError(b, err)
	signerPk := signerSk.PublicKey()

	sign, err := crypto.Sign(data, signerSk)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err = crypto.VerifySignature(data, sign, signerPk); err != nil {
			b.Fatalf("Sing return error: %v", err)
		}
	}
}

func BenchmarkEncrypt(b *testing.B) {
	crypto := cryptocgo.NewVirgilCrypto()

	//make random data
	data := make([]byte, 257)
	rand.Read(data)

	encryptSk, err := crypto.GenerateKeypair()
	require.NoError(b, err)
	encryptPk := encryptSk.PublicKey()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := crypto.Encrypt(data, encryptPk); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecrypt(b *testing.B) {
	crypto := cryptocgo.NewVirgilCrypto()

	//make random data
	data := make([]byte, 257)
	rand.Read(data)

	keypair, err := crypto.GenerateKeypair()
	require.NoError(b, err)

	data, err = crypto.Encrypt(data, keypair.PublicKey())
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err = crypto.Decrypt(data, keypair); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSignAndEncrypt(b *testing.B) {
	crypto := cryptocgo.NewVirgilCrypto()

	//make random data
	data := make([]byte, 257)
	rand.Read(data)

	encryptSk, err := crypto.GenerateKeypair()
	require.NoError(b, err)
	encryptPk := encryptSk.PublicKey()

	signerKeypair, err := crypto.GenerateKeypair()
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := crypto.SignAndEncrypt(data, signerKeypair, encryptPk); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecryptAndVerify(b *testing.B) {
	crypto := cryptocgo.NewVirgilCrypto()

	//make random data
	data := make([]byte, 257)
	rand.Read(data)

	recipientSk, err := crypto.GenerateKeypair()
	require.NoError(b, err)
	recipientPk := recipientSk.PublicKey()

	signerSk, err := crypto.GenerateKeypair()
	require.NoError(b, err)
	signerPk := signerSk.PublicKey()

	data, err = crypto.SignAndEncrypt(data, signerSk, recipientPk)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err = crypto.DecryptAndVerify(data, recipientSk, signerPk); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSignThenEncrypt(b *testing.B) {
	crypto := cryptocgo.NewVirgilCrypto()

	//make random data
	data := make([]byte, 257)
	rand.Read(data)

	encryptSk, err := crypto.GenerateKeypair()
	require.NoError(b, err)
	encryptPk := encryptSk.PublicKey()

	signerKeypair, err := crypto.GenerateKeypair()
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := crypto.SignThenEncrypt(data, signerKeypair, encryptPk); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecryptThenVerify(b *testing.B) {
	crypto := cryptocgo.NewVirgilCrypto()

	//make random data
	data := make([]byte, 257)
	rand.Read(data)

	encryptSk, err := crypto.GenerateKeypair()
	require.NoError(b, err)
	encryptPk := encryptSk.PublicKey()

	signerSk, err := crypto.GenerateKeypair()
	require.NoError(b, err)
	signerPk := signerSk.PublicKey()

	data, err = crypto.SignThenEncrypt(data, signerSk, encryptPk)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err = crypto.DecryptThenVerify(data, encryptSk, signerPk); err != nil {
			b.Fatal(err)
		}
	}
}
