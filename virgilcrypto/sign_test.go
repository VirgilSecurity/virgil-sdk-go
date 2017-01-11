package virgilcrypto

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"gopkg.in/virgil.v4/errors"
)

type badReader struct {
	buf io.Reader
}

func (r *badReader) Read(p []byte) (n int, err error) {
	n, err = r.buf.Read(p[:len(p)-1])
	if err != nil {
		return n, err // not our error
	}
	return n, errors.New("bad reader read one byte less")
}

func TestSignatures(t *testing.T) {
	//make random data
	data := make([]byte, 257)
	rand.Read(data)

	_, err := Signer.Sign(data, &ed25519PrivateKey{})
	if err == nil {
		t.Fatal("must fail with empty keypair")
	}

	keypair, err := NewKeypair()
	if err != nil {
		t.Fatal(err)
	}

	signature, err := Signer.Sign(data, keypair.PrivateKey())
	if err != nil {
		t.Fatal(err)
	}

	//bad key

	result, err := Verifier.Verify(data, nil, signature)
	if err == nil {
		t.Fatal("must fail with nil key")
	}

	result, err = Verifier.Verify(data, &ed25519PublicKey{}, signature)
	if err == nil {
		t.Fatal("must fail with bad key")
	}

	result, err = Verifier.Verify(data, keypair.PublicKey(), data)
	if err == nil {
		t.Fatal("must fail with bad signature")
	}

	badSignature, err := makeSignature(make([]byte, 1))

	result, err = Verifier.Verify(data, keypair.PublicKey(), badSignature)
	if err == nil {
		t.Fatal("must fail with bad signature size")
	}

	result, err = Verifier.Verify(data, keypair.PublicKey(), signature)

	if err != nil {
		t.Fatal(err)
	}
	if !result {
		t.Fatal("Signature verification failed")
	}

	//corrupt key
	keypair.PublicKey().Contents()[0] = ^keypair.PublicKey().Contents()[0]
	keypair.PublicKey().Contents()[1] = ^keypair.PublicKey().Contents()[1]

	result, err = Verifier.Verify(data, keypair.PublicKey(), signature)

	if err == nil {
		t.Fatal("Signature verification succeeded but must fail")
	}
	if result {
		t.Fatal("Signature verification succeeded but must fail")
	}
}

func TestStreamSignatures(t *testing.T) {
	//make random data
	data := make([]byte, 255)
	rand.Read(data)

	keypair, err := NewKeypair()
	if err != nil {
		t.Fatal(err)
	}

	badbuf := &badReader{buf: bytes.NewBuffer(data)}
	signature, err := Signer.SignStream(badbuf, keypair.PrivateKey())
	if err == nil {
		t.Fatal("read must fail")
	}

	buf := bytes.NewBuffer(data)
	signature, err = Signer.SignStream(buf, keypair.PrivateKey())
	if err != nil {
		t.Fatal(err)
	}

	buf = bytes.NewBuffer(data)
	result, err := Verifier.VerifyStream(buf, keypair.PublicKey(), signature)

	if err != nil {
		t.Fatal(err)
	}
	if !result {
		t.Fatal("Signature verification failed")
	}

	//corrupt key
	keypair.PublicKey().Contents()[0] = ^keypair.PublicKey().Contents()[0]
	keypair.PublicKey().Contents()[1] = ^keypair.PublicKey().Contents()[1]
	buf = bytes.NewBuffer(data)
	result, err = Verifier.VerifyStream(buf, keypair.PublicKey(), signature)

	if err == nil {
		t.Fatal("Signature verification succeeded but must fail")
	}
	if result {
		t.Fatal("Signature verification succeeded but must fail")
	}

	badbuf = &badReader{buf: bytes.NewBuffer(data)}
	result, err = Verifier.VerifyStream(badbuf, keypair.PublicKey(), signature)

	if err == nil {
		t.Fatal("read must fail")
	}
	if result {
		t.Fatal("Signature verification succeeded but must fail")
	}
}
