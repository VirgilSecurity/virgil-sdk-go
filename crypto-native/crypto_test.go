package cryptonative

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestSignEncrypt(t *testing.T) {
	crypto := DefaultCrypto

	//make random data
	data := make([]byte, 257)
	rand.Read(data)

	keypair, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	signerKeypair, err := NewKeypair()
	if err != nil {
		t.Fatal(err)
	}

	cipherText, err := crypto.SignThenEncrypt(data, signerKeypair.PrivateKey(), keypair.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	if plaintext, err := crypto.DecryptThenVerify(cipherText, keypair.PrivateKey(), signerKeypair.PublicKey()); err != nil || !bytes.Equal(plaintext, data) {
		t.Fatal(err)
	}

}
