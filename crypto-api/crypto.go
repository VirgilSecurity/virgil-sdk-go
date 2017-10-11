package cryptoapi

type Crypto interface {
	Sign(data []byte, key PrivateKey) ([]byte, error)
	VerifySignature(data []byte, sign []byte, key PublicKey) error
	CalculateFingerprint(data []byte) []byte
	ImportPublicKey(publicKeySrc []byte) (PublicKey, error)
	ExportPublicKey(key PublicKey) ([]byte, error)
}

type PrivateKey interface{}
type PublicKey interface{}
