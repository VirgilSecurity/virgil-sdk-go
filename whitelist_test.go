package virgil

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/virgil.v5/crypto-native"
)

var crypto = &cryptonative.CardCrypto{Crypto: &cryptonative.VirgilCrypto{}}

type testCredentials struct {
	*VerifierCredentials
	PrivateKey cryptonative.PrivateKey
}

func TestWhitelist(t *testing.T) {

	pk, cardCreds := makeRandomCredentials()

	var creds []*testCredentials
	for i := 0; i < 5; i++ {
		pk, cred := makeRandomCredentials()
		creds = append(creds, &testCredentials{VerifierCredentials: cred, PrivateKey: pk})
	}

	var wl []*Whitelist

	wl = addWhitelist(wl, creds[0], creds[1])

	wl = addWhitelist(wl, creds[2])

	cardsManager := &CardsManager{}
	csr, err := cardsManager.GenerateCSR(&CSRParams{
		PrivateKey: pk,
		PublicKey:  cardCreds.PublicKey,
		Identity:   cardCreds.Signer,
	})
	assert.NoError(t, err)

	addSign(t, csr, creds[0])
	addSign(t, csr, creds[1])
	addSign(t, csr, creds[2])

	validator := &ExtendedValidator{IgnoreSelfSignature: true, IgnoreVirgilSignature: true, WhiteList: wl}

	card := &Card{
		Snapshot: csr.Snapshot,
	}

	for _, sig := range csr.Signatures {
		card.Signature = append(card.Signature, &CardSignature{
			Signature: sig.Signature,
			Snapshot:  sig.ExtraFields,
			Signer:    sig.Signer,
		})
	}

	//check default case
	err = validator.Validate(crypto, card)
	assert.NoError(t, err)

	//check that everything is ok if at least one signature in whitelist is valid
	wl[0].VerifierCredentials[0] = creds[4].VerifierCredentials

	err = validator.Validate(crypto, card)
	assert.NoError(t, err)

	//Check that verification fails if no signature exists for whitelist
	wl = addWhitelist(wl, creds[3])
	validator.WhiteList = wl

	err = validator.Validate(crypto, card)
	assert.Error(t, err)

	//empty whitelist must fail
	validator.WhiteList = []*Whitelist{{}}
	err = validator.Validate(crypto, card)
	assert.Error(t, err)

}
func addSign(t *testing.T, csr *CSR, credentials *testCredentials) {
	err := csr.Sign(crypto, &CSRSignParams{
		Signer:           credentials.Signer,
		SignerPrivateKey: credentials.PrivateKey,
		ExtraFields: map[string]string{
			"a": "b",
			"b": "c",
			"x": "y",
			"z": credentials.Signer,
		},
	})
	assert.NoError(t, err)
}

func addWhitelist(wl []*Whitelist, creds ...*testCredentials) []*Whitelist {

	twl := &Whitelist{}

	for _, cred := range creds {
		twl.VerifierCredentials = append(twl.VerifierCredentials, cred.VerifierCredentials)
	}

	wl = append(wl, twl)
	return wl
}

func makeRandomCredentials() (cryptonative.PrivateKey, *VerifierCredentials) {
	kp, err := crypto.Crypto.GenerateKeypair()
	if err != nil {
		panic(err)
	}

	id := make([]byte, 32)
	rand.Read(id)

	return kp.PrivateKey(), &VerifierCredentials{
		Signer:    hex.EncodeToString(id),
		PublicKey: kp.PublicKey(),
	}
}
