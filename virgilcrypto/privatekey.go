package virgilcrypto

import (
	"bytes"
	"encoding/asn1"
	"encoding/pem"

	"github.com/agl/ed25519"
)

type PrivateKey interface {
	Contents() []byte
	ReceiverID() []byte
	ExtractPublicKey() (PublicKey, error)
	Encode(password []byte) ([]byte, error)
	Empty() bool
}

type ed25519PrivateKey struct {
	receiverID []byte
	key        []byte
}

func DecodePrivateKey(keyBytes, password []byte) (key PrivateKey, err error) {
	unwrappedKey, keyType, err := unwrapKey(keyBytes)
	if err != nil {
		return nil, err
	}

	if keyType != "" && keyType != EC_PRIVATE_KEY && keyType != ENCRYPTED_PRIVATE_KEY {
		return nil, unsupported("key type")
	}

	if len(password) == 0 {
		key, err = loadPlainPrivateKey(unwrappedKey)
	} else {
		key, err = loadEncryptedPrivateKey(unwrappedKey, password)
	}
	return
}

func (k *ed25519PrivateKey) Contents() []byte {
	return k.key
}

func (k *ed25519PrivateKey) ReceiverID() []byte {
	return k.receiverID
}

func (k *ed25519PrivateKey) Encode(password []byte) (res []byte, err error) {
	convertToPem := false
	if len(password) == 0 {
		res, err = encodePrivateKey(k, convertToPem)
	} else {
		res, err = encodePrivateKeyEncrypted(k, password, convertToPem)
	}
	return
}

func encodePrivateKey(privateKey *ed25519PrivateKey, encodeToPem bool) ([]byte, error) {
	if privateKey == nil || len(privateKey.key) != ed25519.PrivateKeySize {
		return nil, unsupported("key size")
	}

	rawKey := make([]byte, 34)
	copy(rawKey[2:], privateKey.key)
	rawKey[0] = 0x4
	rawKey[1] = 0x20

	key := privateKeyAsn{
		Version:    0,
		PrivateKey: rawKey,
		OID: algorithmIdentifierWithOidParameter{
			Algorithm: oidEd25519key,
		},
	}

	serializedKey, err := asn1.Marshal(key)

	if err != nil {
		return nil, cryptoError(err, "")
	}

	if !encodeToPem {
		return serializedKey, nil
	} else {
		block := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: serializedKey,
		}
		return pem.EncodeToMemory(block), nil
	}
}
func encodePrivateKeyEncrypted(privateKey *ed25519PrivateKey, password []byte, encodeToPem bool) ([]byte, error) {

	serializedKey, err := encodePrivateKey(privateKey, false)

	if err != nil {
		return nil, err
	}

	kdfIv, iterations, keyIv, encryptedKey := encryptKeyWithPassword(serializedKey, password)

	alg, err := encodeKeyEncryptionAlgorithm(kdfIv, iterations, keyIv)
	if err != nil {
		return nil, err
	}

	asnKey := envelopeKey{
		CipherText: encryptedKey,
		Algorithm:  *alg,
	}
	envelopeBytes, err := asn1.Marshal(asnKey)

	if err != nil {
		return nil, cryptoError(err, "")
	}

	if !encodeToPem {
		return envelopeBytes, nil
	} else {
		block := &pem.Block{
			Type:  ENCRYPTED_PRIVATE_KEY,
			Bytes: envelopeBytes,
		}
		return pem.EncodeToMemory(block), nil
	}
}
func loadPlainPrivateKey(keyBytes []byte) (*ed25519PrivateKey, error) {

	key := &privateKeyAsn{}
	_, err := asn1.Unmarshal(keyBytes, key)
	if err != nil {
		return nil, cryptoError(err, "invalid data")
	}

	err = key.Validate()
	if err != nil {
		return nil, err
	}

	rawKey := key.PrivateKey[2:]
	buf := bytes.NewBuffer(rawKey)

	pub, priv, err := ed25519.GenerateKey(buf)
	if err != nil {
		return nil, cryptoError(err, "could not generate key")
	}

	edPub := &ed25519PublicKey{key: pub[:]}
	edpriv := &ed25519PrivateKey{key: priv[:]}

	snapshot, err := edPub.Encode()
	if err != nil {
		return nil, cryptoError(err, "")
	}

	fp := DefaultCrypto.CalculateFingerprint(snapshot)
	edpriv.receiverID = fp

	return edpriv, nil
}

func loadEncryptedPrivateKey(keyBytes, password []byte) (*ed25519PrivateKey, error) {
	parsedEncryptedKey := &envelopeKey{}
	_, err := asn1.Unmarshal(keyBytes, parsedEncryptedKey)
	if err != nil {
		return nil, cryptoError(err, "could not parse encrypted key")
	}

	keyIv, kdfIv, iterations, err := decodeKeyEncryptionAlgorithm(&parsedEncryptedKey.Algorithm)
	if err != nil {
		return nil, err
	}

	decryptedKey, err := decryptKeyWithPassword(parsedEncryptedKey.CipherText, keyIv, kdfIv, iterations, password)
	if err != nil {
		return nil, &WrongPasswordError{"could not decrypt key with password"}
	}
	key, err := loadPlainPrivateKey(decryptedKey)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (k *ed25519PrivateKey) Empty() bool {
	return k == nil || len(k.key) == 0
}

func (k *ed25519PrivateKey) ExtractPublicKey() (PublicKey, error) {
	if k.Empty() {
		return nil, CryptoError("private key is empty")
	}

	buf := bytes.NewBuffer(k.key)

	pub, _, err := ed25519.GenerateKey(buf)
	if err != nil {
		return nil, cryptoError(err, "could not generate key")
	}

	edPub := &ed25519PublicKey{key: pub[:]}

	edPub.receiverID = make([]byte, len(k.receiverID))
	copy(edPub.receiverID, k.receiverID)
	return edPub, nil
}
