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
		SKa, SKb, AD, SessionID []byte
		Initiator               bool
	}

	PFS interface {
		StartPFSSession(ICb, LTCb, OTCb PublicKey, ICa, EKa PrivateKey, additionalData []byte) (sess *PFSSession, err error)
		ReceivePFCSession(ICa, EKa PublicKey, ICb, LTCb, OTCb PrivateKey, additionalData []byte) (sess *PFSSession, err error)
	}
)

var virgil = []byte("Virgil")

func (c *VirgilCrypto) StartPFSSession(ICb, LTCb, OTCb PublicKey, ICa, EKa PrivateKey, additionalData []byte) (sess *PFSSession, err error) {

	sk, err := EDHInit(ICa, EKa, ICb, LTCb, OTCb)
	if err != nil {
		return
	}

	ska, skb, sid := sk[:32], sk[32:64], sk[64:]

	kdf := hkdf.New(sha256.New, sid, additionalData, virgil)

	sessionID := make([]byte, 32)
	kdf.Read(sessionID)

	return &PFSSession{
		Initiator: true,
		SKa:       ska,
		SKb:       skb,
		AD:        additionalData,
		SessionID: sessionID,
	}, nil

}

func (c *VirgilCrypto) ReceivePFCSession(ICa, EKa PublicKey, ICb, LTCb, OTCb PrivateKey, additionalData []byte) (sess *PFSSession, err error) {

	sk, err := EDHRespond(ICa, EKa, ICb, LTCb, OTCb)
	if err != nil {
		return
	}
	ska, skb, sid := sk[:32], sk[32:64], sk[64:]

	kdf := hkdf.New(sha256.New, sid, additionalData, virgil)

	sessionID := make([]byte, 32)
	kdf.Read(sessionID)

	return &PFSSession{
		Initiator: false,
		SKa:       ska,
		SKb:       skb,
		AD:        additionalData,
		SessionID: sessionID,
	}, nil

}

func (s *PFSSession) Encrypt(plaintext []byte) (salt, ciphertext []byte) {
	salt = make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		panic(err)
	}

	keyAndNonce := make([]byte, 44)

	sk := s.SKa

	if !s.Initiator {
		sk = s.SKb
	}

	kdf := hkdf.New(sha256.New, sk, salt, virgil)

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
	if salt == nil && ciphertext == nil {
		return nil, nil
	}

	keyAndNonce := make([]byte, 44)

	sk := s.SKb

	if !s.Initiator {
		sk = s.SKa
	}

	kdf := hkdf.New(sha256.New, sk, salt, virgil)

	_, err := kdf.Read(keyAndNonce)
	if err != nil {
		panic(err)
	}

	ciph, _ := aes.NewCipher(keyAndNonce[:32])
	aesGCM, _ := cipher.NewGCM(ciph)
	return aesGCM.Open(nil, keyAndNonce[32:], ciphertext, s.AD)
}
