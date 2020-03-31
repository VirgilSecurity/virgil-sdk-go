package crypto

import (
	"github.com/VirgilSecurity/virgil-sdk-go/v6/crypto/wrapper/foundation"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestGetKeyType(t *testing.T) {
	c := &Crypto{}
	for kt := Rsa2048; kt <= Curve25519Round5; kt++ {
		sk, err := c.GenerateKeypairForType(kt)
		require.NoError(t, err)
		gkt, err := GetKeyType(sk.Unwrap().(foundation.Key))
		require.NoError(t, err)
		require.Equal(t, kt, gkt)
	}
}
