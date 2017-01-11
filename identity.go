package virgil

type VerifyRequest struct {
	Type        string
	Value       string
	ExtraFields map[string]string
}

type VerifyResponse struct {
	ActionId string
}

type ValidationTokenParams struct {
	TimeToLive  int
	CountToLive int
}
type ConfirmRequest struct {
	ConfirmationCode string
	ActionId         string
	Params           ValidationTokenParams
}

type ConfirmResponse struct {
	Type            string
	Value           string
	ValidationToken string
}

type ValidateRequest struct {
	Type            string
	Value           string
	ValidationToken string
}
