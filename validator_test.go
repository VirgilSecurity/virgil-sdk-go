package virgil

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidate_EmptyCard_ReturnFalse(t *testing.T) {
	validator := NewCardsValidator()
	card := &Card{}
	ok, err := validator.Validate(card)

	assert.False(t, ok)
	assert.NotNil(t, err)
}

func TestValidate_CardV3_ReturnTrue(t *testing.T) {
	validator := NewCardsValidator()
	card := &Card{}
	card.CardVersion = "3.0"
	card.Snapshot = make([]byte, 1)
	ok, err := validator.Validate(card)

	assert.True(t, ok)
	assert.Nil(t, err)

}

func TestValidate_EmptySignatures_ReturnFalse(t *testing.T) {
	validator := NewCardsValidator()
	card := &Card{}
	card.Snapshot = make([]byte, 1)
	ok, err := validator.Validate(card)

	assert.False(t, ok)
	assert.NotNil(t, err)
}

func TestValidate_IDBroken_ReturnFalse(t *testing.T) {
	crypto := Crypto()
	validator := NewCardsValidator()
	deviceKeypair, _ := crypto.GenerateKeypair()

	req, _ := NewCreateCardRequest("Device #1", "Smart Iot Device", deviceKeypair.PublicKey(), CardParams{})

	id := "asdfasd"

	card := &Card{
		ID:         id,
		Snapshot:   req.Snapshot,
		Signatures: map[string][]byte{"foo": make([]byte, 1)},
		PublicKey:  deviceKeypair.PublicKey(),
	}

	ok, err := validator.Validate(card)
	assert.False(t, ok)
	assert.NotNil(t, err)
}

func TestValidate_NoSelfSign_ReturnFalse(t *testing.T) {
	crypto := Crypto()
	validator := NewCardsValidator()
	deviceKeypair, _ := crypto.GenerateKeypair()

	req, _ := NewCreateCardRequest("Device #1", "Smart Iot Device", deviceKeypair.PublicKey(), CardParams{})

	fp := crypto.CalculateFingerprint(req.Snapshot)
	id := hex.EncodeToString(fp)

	card := &Card{
		ID:         id,
		Snapshot:   req.Snapshot,
		Signatures: map[string][]byte{"foo": make([]byte, 1)},
		PublicKey:  deviceKeypair.PublicKey(),
	}

	ok, err := validator.Validate(card)

	assert.False(t, ok)
	assert.NotNil(t, err)
}

func TestValidate_BadSelfSign_ReturnFalse(t *testing.T) {
	crypto := Crypto()
	validator := NewCardsValidator()
	deviceKeypair, _ := crypto.GenerateKeypair()

	req, _ := NewCreateCardRequest("Device #1", "Smart Iot Device", deviceKeypair.PublicKey(), CardParams{})

	fp := crypto.CalculateFingerprint(req.Snapshot)
	id := hex.EncodeToString(fp)

	card := &Card{
		ID:         id,
		Snapshot:   req.Snapshot,
		Signatures: map[string][]byte{id: make([]byte, 1)},
		PublicKey:  deviceKeypair.PublicKey(),
	}

	ok, err := validator.Validate(card)

	assert.False(t, ok)
	assert.NotNil(t, err)
}

func TestValidate_OneSignatureMissed_ReturnFalse(t *testing.T) {
	crypto := Crypto()
	validator := NewCardsValidator()

	appKey, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	validator.AddVerifier("app", appKey.PublicKey())
	deviceKeypair, _ := crypto.GenerateKeypair()

	req, _ := NewCreateCardRequest("Device #1", "Smart Iot Device", deviceKeypair.PublicKey(), CardParams{})

	signer := &RequestSigner{}
	signer.SelfSign(req, deviceKeypair.PrivateKey())

	fp := crypto.CalculateFingerprint(req.Snapshot)
	id := hex.EncodeToString(fp)

	card := &Card{
		ID:         id,
		Snapshot:   req.Snapshot,
		Signatures: req.Meta.Signatures,
		PublicKey:  deviceKeypair.PublicKey(),
	}

	ok, err := validator.Validate(card)

	assert.False(t, ok)
	assert.NotNil(t, err)
}

func TestValidate_BadAuthoritySignature_ReturnFalse(t *testing.T) {
	crypto := Crypto()
	validator := NewCardsValidator()

	appKey, _ := crypto.GenerateKeypair()

	validator.AddVerifier("app", appKey.PublicKey())
	deviceKeypair, _ := crypto.GenerateKeypair()

	req, _ := NewCreateCardRequest("Device #1", "Smart Iot Device", deviceKeypair.PublicKey(), CardParams{})

	signer := &RequestSigner{}
	signer.SelfSign(req, deviceKeypair.PrivateKey())
	signer.AuthoritySign(req, "app", deviceKeypair.PrivateKey())

	fp := crypto.CalculateFingerprint(req.Snapshot)
	id := hex.EncodeToString(fp)

	card := &Card{
		ID:         id,
		Snapshot:   req.Snapshot,
		Signatures: req.Meta.Signatures,
		PublicKey:  deviceKeypair.PublicKey(),
	}

	ok, err := validator.Validate(card)

	assert.False(t, ok)
	assert.NotNil(t, err)
}

func TestValidate_CardCorrecec_ReturnTrue(t *testing.T) {
	crypto := Crypto()
	validator := NewCardsValidator()

	appKey, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	validator.AddVerifier("app", appKey.PublicKey())
	deviceKeypair, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	req, err := NewCreateCardRequest("Device #1", "Smart Iot Device", deviceKeypair.PublicKey(), CardParams{})
	if err != nil {
		t.Fatal(err)
	}
	signer := &RequestSigner{}
	signer.SelfSign(req, deviceKeypair.PrivateKey())
	signer.AuthoritySign(req, "app", appKey.PrivateKey())

	fp := crypto.CalculateFingerprint(req.Snapshot)
	id := hex.EncodeToString(fp)

	card := &Card{
		ID:         id,
		Snapshot:   req.Snapshot,
		Signatures: req.Meta.Signatures,
		PublicKey:  deviceKeypair.PublicKey(),
	}

	ok, err := validator.Validate(card)

	assert.True(t, ok)
	assert.Nil(t, err)
}

func Test_makeDefaultCardsValidator_CorrectCardValidation(t *testing.T) {
	var v interface{}
	v, _ = makeDefaultCardsValidator()
	assert.IsType(t, &VirgilCardValidator{}, v)
	cv := v.(*VirgilCardValidator)
	_, ok := cv.validators["3e29d43373348cfb373b7eae189214dc01d7237765e572db685839b64adca853"]
	assert.True(t, ok)
}
