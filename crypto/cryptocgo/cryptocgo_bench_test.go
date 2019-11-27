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
		_, err = crypto.Sign(data, signerKeypair.PrivateKey())
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

	signerKeypair, err := crypto.GenerateKeypair()
	require.NoError(b, err)

	sign, err := crypto.Sign(data, signerKeypair.PrivateKey())
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err = crypto.VerifySignature(data, sign, signerKeypair.PublicKey()); err != nil {
			b.Fatalf("Sing return error: %v", err)
		}
	}
}

func BenchmarkEncrypt(b *testing.B) {
	crypto := cryptocgo.NewVirgilCrypto()

	//make random data
	data := make([]byte, 257)
	rand.Read(data)

	keypair, err := crypto.GenerateKeypair()
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := crypto.Encrypt(data, keypair.PublicKey()); err != nil {
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
		if _, err = crypto.Decrypt(data, keypair.PrivateKey()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSignAndEncrypt(b *testing.B) {
	crypto := cryptocgo.NewVirgilCrypto()

	//make random data
	data := make([]byte, 257)
	rand.Read(data)

	keypair, err := crypto.GenerateKeypair()
	require.NoError(b, err)

	signerKeypair, err := crypto.GenerateKeypair()
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := crypto.SignAndEncrypt(data, signerKeypair.PrivateKey(), keypair.PublicKey()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecryptAndVerify(b *testing.B) {
	crypto := cryptocgo.NewVirgilCrypto()

	//make random data
	data := make([]byte, 257)
	rand.Read(data)

	keypair, err := crypto.GenerateKeypair()
	require.NoError(b, err)

	signerKeypair, err := crypto.GenerateKeypair()
	require.NoError(b, err)

	data, err = crypto.SignAndEncrypt(data, signerKeypair.PrivateKey(), keypair.PublicKey())
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err = crypto.DecryptAndVerify(data, keypair.PrivateKey(), signerKeypair.PublicKey()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSignThenEncrypt(b *testing.B) {
	crypto := cryptocgo.NewVirgilCrypto()

	//make random data
	data := make([]byte, 257)
	rand.Read(data)

	keypair, err := crypto.GenerateKeypair()
	require.NoError(b, err)

	signerKeypair, err := crypto.GenerateKeypair()
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := crypto.SignThenEncrypt(data, signerKeypair.PrivateKey(), keypair.PublicKey()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecryptThenVerify(b *testing.B) {
	crypto := cryptocgo.NewVirgilCrypto()

	//make random data
	data := make([]byte, 257)
	rand.Read(data)

	keypair, err := crypto.GenerateKeypair()
	require.NoError(b, err)

	signerKeypair, err := crypto.GenerateKeypair()
	require.NoError(b, err)

	data, err = crypto.SignThenEncrypt(data, signerKeypair.PrivateKey(), keypair.PublicKey())
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err = crypto.DecryptThenVerify(data, keypair.PrivateKey(), signerKeypair.PublicKey()); err != nil {
			b.Fatal(err)
		}
	}
}
