package virgilcrypto

import (
	"encoding/asn1"
	"encoding/pem"

	"golang.org/x/crypto/ed25519"
)

type PublicKey interface {
	ReceiverID() []byte
	Encode() ([]byte, error)
	Empty() bool
}

type ed25519PublicKey struct {
	receiverID []byte
	key        []byte
}

func DecodePublicKey(keyBytes []byte) (PublicKey, error) {
	unwrappedKey, keyType, err := unwrapKey(keyBytes)
	if err != nil {
		return nil, err
	}

	if keyType != "" && keyType != PUBLIC_KEY {
		return nil, unsupported("key type")
	}

	publicKey := &publicKey{}
	_, err = asn1.Unmarshal(unwrappedKey, publicKey)
	if err != nil {
		return nil, CryptoError("invalid data")
	}
	err = publicKey.Validate()
	if err != nil {
		return nil, err
	}

	key := publicKey.Key.Bytes

	edPublicKey := &ed25519PublicKey{key: key}
	snapshot, err := edPublicKey.Encode()
	if err != nil {
		return nil, err
	}

	fp := DefaultCrypto.CalculateFingerprint(snapshot)
	edPublicKey.receiverID = fp
	return edPublicKey, nil
}

func (k *ed25519PublicKey) contents() []byte {
	return k.key
}

func (k *ed25519PublicKey) ReceiverID() []byte {
	return k.receiverID
}

func (k *ed25519PublicKey) Encode() ([]byte, error) {
	encodeToPem := false
	if len(k.key) != ed25519.PublicKeySize {
		return nil, unsupported("key size")
	}

	key := publicKey{}
	key.Algorithm.Algorithm = oidEd25519key
	key.Key = asn1.BitString{Bytes: k.key}
	rawKey, err := asn1.Marshal(key)
	if err != nil {
		return nil, cryptoError(err, "")
	}
	if !encodeToPem {
		return rawKey, nil
	} else {
		block := &pem.Block{
			Type:  PUBLIC_KEY,
			Bytes: rawKey,
		}
		return pem.EncodeToMemory(block), nil
	}
}

func (k *ed25519PublicKey) Empty() bool {
	return k == nil || len(k.key) == 0
}
