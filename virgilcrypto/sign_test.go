package virgilcrypto

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

type badReader struct {
	buf io.Reader
}

func (r *badReader) Read(p []byte) (n int, err error) {
	n, err = r.buf.Read(p[:len(p)-1])
	if err != nil {
		return n, err // not our error
	}
	return n, CryptoError("bad reader read one byte less")
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

	err = Verifier.Verify(data, nil, signature)
	if err == nil {
		t.Fatal("must fail with nil key")
	}

	err = Verifier.Verify(data, &ed25519PublicKey{}, signature)
	if err == nil {
		t.Fatal("must fail with bad key")
	}

	err = Verifier.Verify(data, keypair.PublicKey(), data)
	if err == nil {
		t.Fatal("must fail with bad signature")
	}

	badSignature, err := makeSignature(make([]byte, 1))

	err = Verifier.Verify(data, keypair.PublicKey(), badSignature)
	if err == nil {
		t.Fatal("must fail with bad signature size")
	}

	err = Verifier.Verify(data, keypair.PublicKey(), signature)

	if err != nil {
		t.Fatal(err)
	}

	//corrupt key
	keypair.PublicKey().(*ed25519PublicKey).contents()[0] = ^keypair.PublicKey().(*ed25519PublicKey).contents()[0]
	keypair.PublicKey().(*ed25519PublicKey).contents()[1] = ^keypair.PublicKey().(*ed25519PublicKey).contents()[1]

	err = Verifier.Verify(data, keypair.PublicKey(), signature)

	if err == nil {
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
	err = Verifier.VerifyStream(buf, keypair.PublicKey(), signature)

	if err != nil {
		t.Fatal(err)
	}

	//corrupt key
	keypair.PublicKey().(*ed25519PublicKey).contents()[0] = ^keypair.PublicKey().(*ed25519PublicKey).contents()[0]
	keypair.PublicKey().(*ed25519PublicKey).contents()[1] = ^keypair.PublicKey().(*ed25519PublicKey).contents()[1]
	buf = bytes.NewBuffer(data)
	err = Verifier.VerifyStream(buf, keypair.PublicKey(), signature)

	if err == nil {
		t.Fatal("Signature verification succeeded but must fail")
	}

	badbuf = &badReader{buf: bytes.NewBuffer(data)}
	err = Verifier.VerifyStream(badbuf, keypair.PublicKey(), signature)

	if err == nil {
		t.Fatal("read must fail")
	}

}

func BenchmarkEd25519Signer_Sign(b *testing.B) {
	keypair, err := NewKeypair()
	if err != nil {
		b.Fatal(err)
	}

	sk := keypair.PrivateKey()

	data := make([]byte, 300)

	for i := 0; i < b.N; i++ {
		Signer.Sign(data, sk)
	}
}

func BenchmarkEd25519Verifier_Verify(b *testing.B) {
	keypair, err := NewKeypair()
	if err != nil {
		b.Fatal(err)
	}

	pk := keypair.PublicKey()

	data := make([]byte, 300)

	sign, err := Signer.Sign(data, keypair.PrivateKey())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verifier.Verify(data, pk, sign)
	}
}
