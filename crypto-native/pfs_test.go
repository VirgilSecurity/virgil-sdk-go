package cryptonative

import (
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

	pfs := c

	ad := append(ICa.PublicKey().ReceiverID(), ICb.PublicKey().ReceiverID()...)

	sessA, err := pfs.StartPFSSession(ICb.PublicKey(), LTCb.PublicKey(), OTCb.PublicKey(), ICa.PrivateKey(), EKa.PrivateKey(), ad)
	assert.NoError(t, err)

	sessB, err := pfs.ReceivePFCSession(ICa.PublicKey(), EKa.PublicKey(), ICb.PrivateKey(), LTCb.PrivateKey(), OTCb.PrivateKey(), ad)
	assert.NoError(t, err)

	msg := make([]byte, 1025)
	rand.Read(msg)

	salt, ciphertext := sessA.Encrypt(msg)

	plaintext, err := sessB.Decrypt(salt, ciphertext)

	assert.NoError(t, err)

	assert.Equal(t, plaintext, msg)

	/*ICab, _ := c.ExportPrivateKey(ICa.PrivateKey(), "")
	EKab, _ := c.ExportPrivateKey(EKa.PrivateKey(), "")
	ICbb, _ := c.ExportPrivateKey(ICb.PrivateKey(), "")
	LTCbb, _ := c.ExportPrivateKey(LTCb.PrivateKey(), "")
	OTCbb, _ := c.ExportPrivateKey(OTCb.PrivateKey(), "")

	vec := map[string]interface{}{
		"ICa":            ICab,
		"EKa":            EKab,
		"ICb":            ICbb,
		"LTCb":           LTCbb,
		"OTCb":           OTCbb,
		"AdditionalData": append(ad, []byte("Virgil")...),
		"SKa":            sessA.SKa,
		"SKb":            sessA.SKb,
		"AD":             sessA.AD,
		"SessionID":      sessA.SessionID,
		"Salt":           salt,
		"Plaintext":      plaintext,
		"Ciphertext":     ciphertext,
	}

	res, _ := json.Marshal(vec)
	fmt.Printf("%s\n\n\n", res)*/

	salt, ciphertext = sessB.Encrypt(msg)

	plaintext, err = sessA.Decrypt(salt, ciphertext)

	assert.NoError(t, err)

	assert.Equal(t, plaintext, msg)

	plaintext, err = sessB.Decrypt(salt, ciphertext)

	assert.Error(t, err)

	assert.NotEqual(t, plaintext, msg)
}

func TestPFSNoOTC(t *testing.T) {

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

	pfs := c

	ad := append(ICa.PublicKey().ReceiverID(), ICb.PublicKey().ReceiverID()...)

	sessA, err := pfs.StartPFSSession(ICb.PublicKey(), LTCb.PublicKey(), nil, ICa.PrivateKey(), EKa.PrivateKey(), ad)
	assert.NoError(t, err)

	sessB, err := pfs.ReceivePFCSession(ICa.PublicKey(), EKa.PublicKey(), ICb.PrivateKey(), LTCb.PrivateKey(), nil, ad)
	assert.NoError(t, err)

	msg := make([]byte, 1025)
	rand.Read(msg)

	salt, ciphertext := sessA.Encrypt(msg)

	plaintext, err := sessB.Decrypt(salt, ciphertext)

	assert.NoError(t, err)

	assert.Equal(t, plaintext, msg)

	/*ICab, _ := c.ExportPrivateKey(ICa.PrivateKey(), "")
	EKab, _ := c.ExportPrivateKey(EKa.PrivateKey(), "")
	ICbb, _ := c.ExportPrivateKey(ICb.PrivateKey(), "")
	LTCbb, _ := c.ExportPrivateKey(LTCb.PrivateKey(), "")

	vec := map[string]interface{}{
		"ICa":         ICab,
		"EKa":         EKab,
		"ICb":         ICbb,
		"LTCb":        LTCbb,
		"AdditionalData": append(ad, []byte("Virgil")...),
		"SKa":         sessA.SKa,
		"SKb":         sessA.SKb,
		"AD":          sessA.AD,
		"SessionID":   sessA.SessionID,
		"Salt":        salt,
		"Plaintext":   plaintext,
		"Ciphertext":  ciphertext,
	}

	res, _ := json.Marshal(vec)
	fmt.Printf("%s", res)*/

	sessB.Initiator = !sessB.Initiator

	plaintext, err = sessB.Decrypt(salt, ciphertext)

	assert.Error(t, err)

	assert.NotEqual(t, plaintext, msg)

}
