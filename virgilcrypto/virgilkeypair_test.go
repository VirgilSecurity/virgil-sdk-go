package virgilcrypto

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
)

func TestKeys(t *testing.T) {

	keypair, err := NewKeypair()
	if err != nil {
		t.Fatal(err)
	}
	pus1, err := keypair.PublicKey().Encode()
	if err != nil {
		t.Fatal(err)
	}
	prs1, err := keypair.PrivateKey().Encode(nil)
	if err != nil {
		t.Fatal(err)
	}

	dPub, err := DecodePublicKey(pus1)
	if err != nil {
		t.Fatal(err)
	}
	dPriv, err := DecodePrivateKey(prs1, nil)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(keypair.PublicKey().Contents(), dPub.Contents()) {
		fmt.Println(keypair.PublicKey().Contents())
		fmt.Println(dPub.Contents())

		t.Fatal("deserialized & original public keys do not match")
	}

	if !bytes.Equal(keypair.PrivateKey().Contents(), dPriv.Contents()) {
		t.Fatal("deserialized & original private keys do not match")
	}

	//check password
	passBytes := make([]byte, 12)
	rand.Read(passBytes)
	prs1, err = dPriv.Encode(passBytes)
	if err != nil {
		t.Fatal(err)
	}

	dPriv, err = DecodePrivateKey(prs1, passBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keypair.PrivateKey().Contents(), dPriv.Contents()) {
		t.Fatal("keys do not match")
	}
}
