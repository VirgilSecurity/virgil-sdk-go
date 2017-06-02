package virgilcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"

	"github.com/minio/sha256-simd"
	"golang.org/x/crypto/hkdf"
)

type (
	PFSSession struct {
		SK, AD, SessionID []byte
	}

	PFS interface {
		StartInitiatorSession(ICb, LTCb, OTCb PublicKey, ICa, EKa PrivateKey, aliceCardId, bobCardId string) (sess *PFSSession, err error)
		StartResponderSession(ICa, EKa PublicKey, ICb, LTCb, OTCb PrivateKey, aliceCardId, bobCardId string) (sess *PFSSession, err error)
	}
)

func (c *VirgilCrypto) StartInitiatorSession(ICb, LTCb, OTCb PublicKey, ICa, EKa PrivateKey, aliceCardId, bobCardId string) (sess *PFSSession, err error) {

	sk, err := X3DHInit(ICa, EKa, ICb, LTCb, OTCb)
	if err != nil {
		return
	}

	return skToSession(sk, aliceCardId, bobCardId), nil

}

func (c *VirgilCrypto) StartResponderSession(ICa, EKa PublicKey, ICb, LTCb, OTCb PrivateKey, aliceCardId, bobCardId string) (sess *PFSSession, err error) {

	sk, err := X3DHRespond(ICa, EKa, ICb, LTCb, OTCb)
	if err != nil {
		return
	}

	return skToSession(sk, aliceCardId, bobCardId), nil

}

func skToSession(sk []byte, aliceCardId, bobCardId string) *PFSSession {
	hash := sha256.New()

	virgil := []byte("Virgil")

	toHash := make([]byte, 0, len(aliceCardId)+len(bobCardId)+len(virgil))
	toHash = append([]byte(aliceCardId), []byte(bobCardId)...)
	toHash = append(toHash, virgil...)

	hash.Write(toHash)
	ad := hash.Sum(nil)
	hash.Reset()

	toHash = toHash[:0]

	toHash = append(sk, ad[:]...)
	toHash = append(toHash, virgil...)

	hash.Write(toHash)
	sessionID := hash.Sum(nil)

	return &PFSSession{
		SK:        sk,
		AD:        ad,
		SessionID: sessionID,
	}
}

func (s *PFSSession) Encrypt(plaintext []byte) (salt, ciphertext []byte) {
	salt = make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		panic(err)
	}

	keyAndNonce := make([]byte, 44)
	kdf := hkdf.New(sha256.New, s.SK, salt, []byte("Virgil"))

	_, err = kdf.Read(keyAndNonce)
	if err != nil {
		panic(err)
	}

	ciph, _ := aes.NewCipher(keyAndNonce[:32])
	aesGCM, _ := cipher.NewGCM(ciph)
	ciphertext = aesGCM.Seal(nil, keyAndNonce[32:], plaintext, s.AD)
	return
}

func (s *PFSSession) Decrypt(salt, ciphertext []byte) ([]byte, error) {

	keyAndNonce := make([]byte, 44)
	kdf := hkdf.New(sha256.New, s.SK, salt, []byte("Virgil"))

	_, err := kdf.Read(keyAndNonce)
	if err != nil {
		panic(err)
	}

	ciph, _ := aes.NewCipher(keyAndNonce[:32])
	aesGCM, _ := cipher.NewGCM(ciph)
	return aesGCM.Open(nil, keyAndNonce[32:], ciphertext, s.AD)
}
