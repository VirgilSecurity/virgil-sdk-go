package virgilcrypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestX3DH(t *testing.T) {

	ICa, err := NewKeypair()
	assert.NoError(t, err)

	EKa, err := NewKeypair()
	assert.NoError(t, err)

	ICb, err := NewKeypair()
	assert.NoError(t, err)

	LTCb, err := NewKeypair()
	assert.NoError(t, err)

	OTCb, err := NewKeypair()
	assert.NoError(t, err)

	sk1, err := X3DHInit(ICa.PrivateKey(), EKa.PrivateKey(), ICb.PublicKey(), LTCb.PublicKey(), OTCb.PublicKey())
	assert.NoError(t, err)

	sk2, err := X3DHRespond(ICa.PublicKey(), EKa.PublicKey(), ICb.PrivateKey(), LTCb.PrivateKey(), OTCb.PrivateKey())

	assert.NoError(t, err)
	assert.Equal(t, sk1, sk2)

	sk2, err = X3DHRespond(ICa.PublicKey(), EKa.PublicKey(), ICb.PrivateKey(), LTCb.PrivateKey(), nil)

	assert.NoError(t, err)
	assert.NotEqual(t, sk1, sk2)

	sk1, err = X3DHInit(ICa.PrivateKey(), EKa.PrivateKey(), ICb.PublicKey(), LTCb.PublicKey(), nil)
	assert.NoError(t, err)
	assert.Equal(t, sk1, sk2)

}
