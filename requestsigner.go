package virgil

import (
	"encoding/hex"

	"gopkg.in/virgil.v4/virgilcrypto"
)

type RequestSigner struct {
}

func (rs *RequestSigner) SelfSign(req *SignableRequest, privateKey virgilcrypto.PrivateKey) error {

	fp := Crypto().CalculateFingerprint(req.Snapshot)

	sign, err := Crypto().Sign(fp, privateKey)

	if err != nil {
		return err
	}
	req.AppendSignature(hex.EncodeToString(fp), sign)
	return nil
}

func (rs *RequestSigner) AuthoritySign(req *SignableRequest, cardId string, privateKey virgilcrypto.PrivateKey) error {

	fp := Crypto().CalculateFingerprint(req.Snapshot)

	sign, err := Crypto().Sign(fp, privateKey)
	if err != nil {
		return err
	}

	req.AppendSignature(cardId, sign)
	return nil
}
