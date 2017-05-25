package virgilcrypto

import (
	"encoding/hex"
	"testing"

	"crypto/rand"

	"github.com/stretchr/testify/assert"
)

func TestPFS(t *testing.T) {

	c := DefaultCrypto

	//ICa, EKa, ICb, LTCb, OTCb
	ICa, err := c.GenerateKeypair()
	assert.NoError(t, err)

	EKa, err := c.GenerateKeypair()
	assert.NoError(t, err)

	ICb, err := c.GenerateKeypair()
	assert.NoError(t, err)

	LTCb, err := c.GenerateKeypair()
	assert.NoError(t, err)

	OTCb, err := c.GenerateKeypair()
	assert.NoError(t, err)

	pfs := c.(PFS)

	aliceCardID := hex.EncodeToString(ICa.PublicKey().ReceiverID())
	bobCardID := hex.EncodeToString(ICb.PublicKey().ReceiverID())

	sessA, err := pfs.StartPFSSession(ICb.PublicKey(), LTCb.PublicKey(), OTCb.PublicKey(), ICa.PrivateKey(), EKa.PrivateKey(), aliceCardID, bobCardID)
	assert.NoError(t, err)

	sessB, err := pfs.ReceivePFCSession(ICa.PublicKey(), EKa.PublicKey(), ICb.PrivateKey(), LTCb.PrivateKey(), OTCb.PrivateKey(), aliceCardID, bobCardID)
	assert.NoError(t, err)

	msg := make([]byte, 1025)
	rand.Read(msg)

	salt, ciphertext := sessA.Encrypt(msg)

	plaintext, err := sessB.Decrypt(salt, ciphertext)

	assert.NoError(t, err)

	assert.Equal(t, plaintext, msg)

}
