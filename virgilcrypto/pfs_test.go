package virgilcrypto

import (
	"encoding/hex"
	"testing"

	"crypto/rand"

	"github.com/stretchr/testify/assert"
)

type TestVector struct {
	ICa, EKa, ICb, LTCb, OTCb   []byte
	AliceCardID, BobCardID      string
	SK, AD, SessionID           []byte
	Salt, Plaintext, Ciphertext []byte
}

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

	sessA, err := pfs.StartInitiatorSession(ICb.PublicKey(), LTCb.PublicKey(), OTCb.PublicKey(), ICa.PrivateKey(), EKa.PrivateKey(), aliceCardID, bobCardID)
	assert.NoError(t, err)

	sessB, err := pfs.StartResponderSession(ICa.PublicKey(), EKa.PublicKey(), ICb.PrivateKey(), LTCb.PrivateKey(), OTCb.PrivateKey(), aliceCardID, bobCardID)
	assert.NoError(t, err)

	assert.Equal(t, sessA.AD, sessB.AD)
	assert.Equal(t, sessA.SessionID, sessB.SessionID)

	assert.NotEqual(t, sessA.AD, sessA.SessionID)
	assert.NotEqual(t, sessB.AD, sessB.SessionID)

	msg := make([]byte, 127)
	rand.Read(msg)

	salt, ciphertext := sessA.Encrypt(msg)

	plaintext, err := sessB.Decrypt(salt, ciphertext)

	assert.NoError(t, err)

	assert.Equal(t, plaintext, msg)

	/*ICab, _ := ICa.PrivateKey().Encode(nil)
	EKab, _ := EKa.PrivateKey().Encode(nil)
	ICbb, _ := ICb.PrivateKey().Encode(nil)
	LTCbb, _ := LTCb.PrivateKey().Encode(nil)
	OTCbb, _ := OTCb.PrivateKey().Encode(nil)

	vec := &TestVector{
		ICa:         ICab,
		EKa:         EKab,
		ICb:         ICbb,
		LTCb:        LTCbb,
		OTCb:        OTCbb,
		AliceCardID: aliceCardID,
		BobCardID:   bobCardID,
		SK:          sessA.SK,
		AD:          sessA.AD,
		SessionID:   sessA.SessionID,
		Salt:        salt,
		Ciphertext:  ciphertext,
		Plaintext:   plaintext,
	}
	res, _ := json.Marshal(vec)
	fmt.Printf("%s\n", res)*/
}
