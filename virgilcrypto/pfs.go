package virgilcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"

	"golang.org/x/crypto/hkdf"
)

type (
	PFSSession struct {
		SK, AD, SessionID []byte
	}

	PFS interface {
		StartPFSSession(ICb, LTCb, OTCb PublicKey, ICa, EKa PrivateKey, aliceCardId, bobCardId string) (sess *PFSSession, err error)
		ReceivePFCSession(ICa, EKa PublicKey, ICb, LTCb, OTCb PrivateKey, aliceCardId, bobCardId string) (sess *PFSSession, err error)
	}
)

func (c *VirgilCrypto) StartPFSSession(ICb, LTCb, OTCb PublicKey, ICa, EKa PrivateKey, aliceCardId, bobCardId string) (sess *PFSSession, err error) {

	sk, err := X3DHInit(ICa, EKa, ICb, LTCb, OTCb)
	if err != nil {
		return
	}

	toHash := make([]byte, 0, len(aliceCardId)+len(bobCardId)+len("Virgil"))
	toHash = append([]byte(aliceCardId), []byte(bobCardId)...)
	toHash = append(toHash, []byte("Virgil")...)

	hash := sha256.Sum256(toHash)

	ad := hash[:]

	toHash = make([]byte, 0, len(sk)+len(ad)+len("Virgil"))

	toHash = append(sk, ad...)
	toHash = append(toHash, []byte("Virgil")...)

	sessHash := sha256.Sum256(toHash)
	sessionID := sessHash[:]

	return &PFSSession{
		SK:        sk,
		AD:        ad,
		SessionID: sessionID,
	}, nil

}

func (c *VirgilCrypto) ReceivePFCSession(ICa, EKa PublicKey, ICb, LTCb, OTCb PrivateKey, aliceCardId, bobCardId string) (sess *PFSSession, err error) {

	sk, err := X3DHRespond(ICa, EKa, ICb, LTCb, OTCb)
	if err != nil {
		return
	}

	toHash := make([]byte, 0, len(aliceCardId)+len(bobCardId)+len("Virgil"))
	toHash = append([]byte(aliceCardId), []byte(bobCardId)...)
	toHash = append(toHash, []byte("Virgil")...)

	hash := sha256.Sum256(toHash)

	ad := hash[:]

	toHash = make([]byte, 0, len(sk)+len(ad)+len("Virgil"))

	toHash = append(sk, ad...)
	toHash = append(toHash, []byte("Virgil")...)

	sessHash := sha256.Sum256(toHash)
	sessionID := sessHash[:]

	return &PFSSession{
		SK:        sk,
		AD:        ad,
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
