package virgilcards

import (
	"errors"

	"gopkg.in/virgil.v6/common"
)

type CardsAPIError common.VirgilAPIError

func (err CardsAPIError) Error() string {
	return common.VirgilAPIError(err).Error()
}

var (
	CSRIdentityEmptyErr        = errors.New("Idneity field in CSR is mandatory")
	CSRSignParamIncorrectErr   = errors.New("CSR signature params incorrect")
	CSRPublicKeyEmptyErr       = errors.New("Public key field in CSR is mandatory")
	CSRSilfSignAlreadyExistErr = errors.New("The CSR is already has self signature")
	CSRAppSignAlreadyExistErr  = errors.New("The CSR is already has application signature")

	CardValidationSignerTypeIncorrectErr       = errors.New("Card validation: signer type incorrect")
	CardValidationExpectedSignerWasNotFoundErr = errors.New("Card validation: expected signer was not found")
)
