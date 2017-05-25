package virgilcrypto

import (
	"github.com/agl/ed25519"
	"github.com/agl/ed25519/extra25519"
	"github.com/minio/sha256-simd"
	"github.com/pkg/errors"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

func X3DHInit(ICa, EKa PrivateKey, ICb, LTCb, OTCb PublicKey) ([]byte, error) {

	edICa, ok := ICa.(*ed25519PrivateKey)
	if !ok {
		return nil, cryptoError(errors.New("non ed25519 private key"), "ICa")
	}

	edEKa, ok := EKa.(*ed25519PrivateKey)
	if !ok {
		return nil, cryptoError(errors.New("non ed25519 private key"), "EKa")
	}

	edICb, ok := ICb.(*ed25519PublicKey)
	if !ok {
		return nil, cryptoError(errors.New("non ed25519 public key"), "ICb")
	}

	edLTCb, ok := LTCb.(*ed25519PublicKey)
	if !ok {
		return nil, cryptoError(errors.New("non ed25519 public key"), "LTCb")
	}

	dh1, err := dhED25519(edICa, edLTCb)
	if err != nil {
		return nil, err
	}

	dh2, err := dhED25519(edEKa, edICb)
	if err != nil {
		return nil, err
	}

	dh3, err := dhED25519(edEKa, edLTCb)
	if err != nil {
		return nil, err
	}

	sk := append(dh1, dh2...)
	sk = append(sk, dh3...)

	if OTCb != nil {

		edOTCb, ok := OTCb.(*ed25519PublicKey)
		if !ok {
			return nil, cryptoError(errors.New("non ed25519 public key"), "LTCb")
		}

		dh4, err := dhED25519(edEKa, edOTCb)
		if err != nil {
			return nil, err
		}

		sk = append(sk, dh4...)
	}

	kdf := hkdf.New(sha256.New, sk, nil, nil)

	res := make([]byte, 64)
	kdf.Read(res)
	return res, nil

}

func X3DHRespond(ICa, EKa PublicKey, ICb, LTCb, OTCb PrivateKey) ([]byte, error) {

	edICa, ok := ICa.(*ed25519PublicKey)
	if !ok {
		return nil, cryptoError(errors.New("non ed25519 public key"), "ICa")
	}

	edEKa, ok := EKa.(*ed25519PublicKey)
	if !ok {
		return nil, cryptoError(errors.New("non ed25519 public key"), "EKa")
	}

	edICb, ok := ICb.(*ed25519PrivateKey)
	if !ok {
		return nil, cryptoError(errors.New("non ed25519 private key"), "ICb")
	}

	edLTCb, ok := LTCb.(*ed25519PrivateKey)
	if !ok {
		return nil, cryptoError(errors.New("non ed25519 private key"), "LTCb")
	}

	dh1, err := dhED25519(edLTCb, edICa)
	if err != nil {
		return nil, err
	}

	dh2, err := dhED25519(edICb, edEKa)
	if err != nil {
		return nil, err
	}

	dh3, err := dhED25519(edLTCb, edEKa)
	if err != nil {
		return nil, err
	}

	sk := append(dh1, dh2...)
	sk = append(sk, dh3...)

	if OTCb != nil {

		edOTCb, ok := OTCb.(*ed25519PrivateKey)
		if !ok {
			return nil, cryptoError(errors.New("non ed25519 private key"), "LTCb")
		}

		dh4, err := dhED25519(edOTCb, edEKa)
		if err != nil {
			return nil, err
		}

		sk = append(sk, dh4...)
	}

	kdf := hkdf.New(sha256.New, sk, nil, nil)

	res := make([]byte, 64)
	kdf.Read(res)
	return res, nil

}

func dhED25519(priv *ed25519PrivateKey, pub *ed25519PublicKey) ([]byte, error) {

	edPub := new([ed25519.PublicKeySize]byte)
	edPriv := new([ed25519.PrivateKeySize]byte)

	curvePriv := new([Curve25519PrivateKeySize]byte)
	curvePub := new([Curve25519PublicKeySize]byte)

	copy(edPub[:], pub.contents())
	copy(edPriv[:], priv.contents())

	extra25519.PublicKeyToCurve25519(curvePub, edPub)
	extra25519.PrivateKeyToCurve25519(curvePriv, edPriv)

	sk := new([Curve25519SharedKeySize]byte)
	curve25519.ScalarMult(sk, curvePriv, curvePub)

	return sk[:], checkSharedSecret(sk[:])
}
