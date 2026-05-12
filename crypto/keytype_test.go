package crypto

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetKeyType(t *testing.T) {
	c := &Crypto{}
	types := []KeyType{
		RsaKey(2048), RsaKey(4096),
		P256r1, Curve25519, Ed25519,
		Curve25519Ed25519,
		Curve25519MlKem768Ed25519Falcon,
		HybridKEM(AlgCurve25519, AlgMlKem768),
		CompoundKey(AlgCurve25519, AlgNone, AlgEd25519, AlgMlDsa65),
	}
	for _, kt := range types {
		sk, err := c.GenerateKeypairForType(kt)
		require.NoError(t, err)
		require.Equal(t, kt, sk.KeyType())
		require.Equal(t, kt, sk.PublicKey().KeyType())
	}
}
