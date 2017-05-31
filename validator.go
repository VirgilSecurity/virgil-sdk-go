package virgil

import (
	"encoding/hex"
	"strings"

	"gopkg.in/virgil.v4/errors"
	"gopkg.in/virgil.v4/virgilcrypto"
)

// A CardsValidator validate response from server
// Validator check that a card was signed by all services
type CardsValidator interface {
	//if the result is false then error must not be nil
	Validate(card *Card) (bool, error)
}

// NewCardsValidator create a cards validator
func NewCardsValidator() *VirgilCardValidator {
	validator := &VirgilCardValidator{
		validators: make(map[string]virgilcrypto.PublicKey),
	}

	return validator
}

type VirgilCardValidator struct {
	validators map[string]virgilcrypto.PublicKey
}

// Validate that all signatures were added
func (v *VirgilCardValidator) Validate(card *Card) (bool, error) {
	if card == nil || len(card.Snapshot) == 0 {
		return false, errors.New("nil card")
	}
	// Support for legacy Cards.
	if card.CardVersion == "3.0" && card.Scope == CardScope.Global {
		return true, nil
	}
	if len(card.Signatures) == 0 {
		return false, errors.New("no signatures provided")
	}

	fp := Crypto().CalculateFingerprint(card.Snapshot)

	//check that id looks like fingerprint
	hexfp := hex.EncodeToString(fp)
	if !strings.EqualFold(hexfp, card.ID) {
		return false, errors.Errorf("card id %s does not match fingerprint %s", card.ID, hexfp)
	}

	//check self signature
	selfsign, ok := card.Signatures[hexfp]
	if !ok {
		return false, errors.Errorf("no self signature found for card " + card.ID)
	}

	valid, err := Crypto().Verify(fp, selfsign, card.PublicKey)
	if !valid {
		return false, errors.Wrap(err, "self signature validation failed")
	}

	for id, key := range v.validators {
		sign, ok := card.Signatures[id]
		if !ok {
			return false, errors.Errorf("Card %s does not have signature for verifier ID %s", card.ID, id)
		}

		valid, err := Crypto().Verify(fp, sign, key)
		if !valid {
			return false, errors.Wrap(err, "signature validation failed")
		}
	}
	return true, nil
}

// AddVerifier add new service for validation
func (v *VirgilCardValidator) AddVerifier(cardId string, key virgilcrypto.PublicKey) {
	v.validators[cardId] = key
}

// AddVerifier adds default card service card
func (v *VirgilCardValidator) AddDefaultVerifiers() error {
	crypto := Crypto()

	key, err := crypto.ImportPublicKey([]byte(`-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAYR501kV1tUne2uOdkw4kErRRbJrc2Syaz5V1fuG+rVs=
-----END PUBLIC KEY-----`))

	if err != nil {
		return err
	}
	v.AddVerifier("3e29d43373348cfb373b7eae189214dc01d7237765e572db685839b64adca853", key)
	return nil
}

func MakeDefaultCardsValidator() (CardsValidator, error) {

	validator := NewCardsValidator()
	err := validator.AddDefaultVerifiers()
	if err != nil {
		return nil, err
	}
	return validator, nil
}
