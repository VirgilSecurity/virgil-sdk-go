package virgilcards

import (
	"encoding/hex"
	"encoding/json"

	"github.com/pkg/errors"
	cryptoapi "gopkg.in/virgil.v6/crypto-api"
)

type CSRParams struct {
	Identity    string
	PublicKey   cryptoapi.PublicKey
	PrivateKey  cryptoapi.PrivateKey
	ExtraFields map[string]string
}
type CSRSignParams struct {
	SignerCardId     string
	SignerType       SignerType
	SignerPrivateKey cryptoapi.PrivateKey
	ExtraFields      map[string]string
}

type CSR struct {
	ID             string
	Identity       string
	PublicKeyBytes []byte
	Version        string
	CreatedAt      int64
	Snapshot       []byte
	Signatures     []RawCardSignature
}

func sliceIndex(n int, predicate func(i int) bool) int {
	for i := 0; i < n; i++ {
		if predicate(i) {
			return i
		}
	}
	return -1
}

func (csr *CSR) Sign(crypto cryptoapi.Crypto, param CSRSignParams) error {
	if param.SignerCardId == "" || param.SignerPrivateKey == nil || param.SignerType == "" {
		return CSRSignParamIncorrectErr
	}

	if param.SignerType == SignerTypeSelf || param.SignerType == SignerTypeApplication { // check self and app sign is unique
		index := sliceIndex(len(csr.Signatures), func(i int) bool {
			return csr.Signatures[i].SignerType == string(param.SignerType)
		})
		if index != -1 {
			if param.SignerType == SignerTypeSelf {
				return CSRSilfSignAlreadyExistErr
			}
			return CSRAppSignAlreadyExistErr
		}
	}

	var extraSnapshot []byte
	var err error
	signingSnapshot := csr.Snapshot
	if len(param.ExtraFields) != 0 {
		extraSnapshot, err = json.Marshal(param.ExtraFields)
		if err != nil {
			return errors.Wrap(err, "CSR.Sign: marshaling extra fields")
		}
		signingSnapshot = append(signingSnapshot, extraSnapshot...)
	}

	if param.SignerType == SignerTypeSelf {
		param.SignerCardId = hex.EncodeToString(crypto.CalculateFingerprint(signingSnapshot))
		csr.ID = param.SignerCardId
	}

	sign, err := crypto.Sign(signingSnapshot, param.SignerPrivateKey)
	if err != nil {
		return err
	}
	csr.Signatures = append(csr.Signatures, RawCardSignature{
		ExtraFields:  extraSnapshot,
		Signature:    sign,
		SignerCardId: param.SignerCardId,
		SignerType:   string(param.SignerType),
	})

	return nil
}
