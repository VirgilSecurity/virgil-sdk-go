package virgilcrypto

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/agl/ed25519/extra25519"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
)

func TestECIES(t *testing.T) {

	kp, err := NewKeypair()
	if err != nil {
		t.Fatal(err)
	}
	symmetricKey := make([]byte, 32)

	rand.Read(symmetricKey)

	encryptedSymmetricKey, tag, ephPub, iv, err := encryptSymmetricKeyWithECIES(kp.PublicKey().Contents(), symmetricKey)

	if err != nil {
		t.Fatal(err)
	}

	decryptedKey, err := decryptSymmetricKeyWithECIES(encryptedSymmetricKey, tag, ephPub, iv, kp.PrivateKey().Contents())

	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(symmetricKey, decryptedKey) {
		t.Fatal("symmetric key and decrypted key are different")
	}
}

func TestEdToCurve(t *testing.T) {
	ephKeypair, err := NewKeypair()
	if err != nil {
		t.Fatal(err)
	}
	hisKeypair, err := NewKeypair()
	if err != nil {
		t.Fatal(err)
	}
	ephPrivate := new([ed25519.PrivateKeySize]byte)
	ephCurvePrivate := new([Curve25519PrivateKeySize]byte)
	ephPublic := new([ed25519.PublicKeySize]byte)
	ephCurvePublic := new([Curve25519PublicKeySize]byte)

	hisPrivate := new([ed25519.PrivateKeySize]byte)
	hisCurvePrivate := new([Curve25519PrivateKeySize]byte)
	hisPublic := new([ed25519.PublicKeySize]byte)
	hisCurvePublic := new([Curve25519PublicKeySize]byte)

	copy(hisPrivate[:], hisKeypair.PrivateKey().Contents())
	copy(hisPublic[:], hisKeypair.PublicKey().Contents())
	copy(ephPrivate[:], ephKeypair.PrivateKey().Contents())
	copy(ephPublic[:], ephKeypair.PublicKey().Contents())

	extra25519.PrivateKeyToCurve25519(ephCurvePrivate, ephPrivate)
	extra25519.PublicKeyToCurve25519(hisCurvePublic, hisPublic)

	extra25519.PrivateKeyToCurve25519(hisCurvePrivate, hisPrivate)
	extra25519.PublicKeyToCurve25519(ephCurvePublic, ephPublic)

	sharedSecret1 := new([Curve25519SharedKeySize]byte)
	curve25519.ScalarMult(sharedSecret1, ephCurvePrivate, hisCurvePublic)
	sharedSecret2 := new([Curve25519SharedKeySize]byte)
	curve25519.ScalarMult(sharedSecret2, hisCurvePrivate, ephCurvePublic)

	zeroSecret := new([Curve25519SharedKeySize]byte)
	if bytes.Equal(zeroSecret[:], sharedSecret1[:]) || (!bytes.Equal(sharedSecret1[:], sharedSecret2[:])) {
		t.Fatal("shared keys are different or all zeroes")
	}
}
