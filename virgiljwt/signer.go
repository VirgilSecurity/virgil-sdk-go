package virgiljwt

import (
	"github.com/dgrijalva/jwt-go"

	cryptoapi "gopkg.in/virgil.v6/crypto-api"
)

//
// Virgil signing constants.
//
const (
	VirgilSigningAlgorithm = "VIRGIL"
)

//
// init registers Virgil Security token validator.
//
func init() {
	jwt.RegisterSigningMethod(VirgilSigningAlgorithm, makeVirgilSigningMethod)
}

//
// GetVirgilSigningMethod returns an instance of Virgil signing method.
//
func makeVirgilSigningMethod() jwt.SigningMethod {
	return new(virgilSigner)
}

type secretKey struct {
	Crypto cryptoapi.Crypto
	Key    cryptoapi.PrivateKey
}

type publicKey struct {
	Crypto cryptoapi.Crypto
	Key    cryptoapi.PublicKey
}

//
// virgilSigner is a Virgil Security implementation for the token signing.
//
type virgilSigner struct{}

//
// Verify performs token verification.
// Expects key to be virgilcrypto.PublicKey
//
func (s *virgilSigner) Verify(signingString, signature string, key interface{}) error {
	pk, ok := key.(publicKey)
	if !ok {
		return jwt.ErrInvalidKeyType
	}

	decodedSignature, err := jwt.DecodeSegment(signature)
	if nil != err {
		return ErrSignatureDecode
	}

	err = pk.Crypto.VerifySignature([]byte(signingString), decodedSignature, pk.Key)
	if err != nil {
		return ErrSignatureIsInvalid
	}

	return nil
}

//
// Sign performs token signing.
// Expects key to be virgilcrypto.PrivateKey instance.
//
func (s *virgilSigner) Sign(signingString string, key interface{}) (string, error) {
	sk, ok := key.(secretKey)
	if !ok {
		return "", jwt.ErrInvalidKeyType
	}

	signature, err := sk.Crypto.Sign([]byte(signingString), sk.Key)
	if nil != err {
		return "", err
	}

	return jwt.EncodeSegment(signature), nil
}

//
// Alg returns signer algorithm name.
//
func (s *virgilSigner) Alg() string {
	return VirgilSigningAlgorithm
}
