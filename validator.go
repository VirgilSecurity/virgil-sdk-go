package virgilcards

import "gopkg.in/virgil.v6/crypto-api"

type SignerInfo struct {
	CardID    string
	PublicKey cryptoapi.PublicKey
}

var VirgilSignerInfo = SignerInfo{
	CardID: "3e29d43373348cfb373b7eae189214dc01d7237765e572db685839b64adca853",
}

type ExtendedValidator struct {
	WhiteList             []SignerInfo
	IgnoreSelfSignature   bool
	IgnoreVirgilSignature bool
}

func (v *ExtendedValidator) Validate(crypto cryptoapi.Crypto, card Card) (err error) {
	if !v.IgnoreSelfSignature {
		err = v.checkSign(crypto, card, SignerInfo{CardID: card.ID, PublicKey: card.PublicKey}, SignerTypeSelf)
		if err != nil {
			return err
		}
	}
	if !v.IgnoreVirgilSignature {
		err = v.checkSign(crypto, card, VirgilSignerInfo, SignerTypeVirgil)
		if err != nil {
			return err
		}
	}
	if len(v.WhiteList) == 0 {
		return nil
	}
	for _, signer := range v.WhiteList {
		err = v.checkSign(crypto, card, signer, SignerTypeCustom)
		if err == CardValidationExpectedSignerWasNotFoundErr {
			continue
		}
		if err != nil {
			return err
		}
		return nil
	}
	return CardValidationExpectedSignerWasNotFoundErr
}

func (v *ExtendedValidator) checkSign(crypto cryptoapi.Crypto, card Card, signer SignerInfo, signerType SignerType) error {
	if len(card.Signature) == 0 {
		return CardValidationExpectedSignerWasNotFoundErr
	}
	for _, s := range card.Signature {
		if s.SignerCardId == signer.CardID {
			if s.SignerType != signerType {
				return CardValidationSignerTypeIncorrectErr
			}
			snapshot := append(card.Snapshot, s.Snapshot...)
			err := crypto.VerifySignature(snapshot, s.Signature, signer.PublicKey)
			if err != nil {
				return err
			}
		}
	}
	return CardValidationExpectedSignerWasNotFoundErr
}
