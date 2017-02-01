package virgil

type VerifyRequest struct {
	Type        string            `json:"type"`
	Value       string            `json:"value"`
	ExtraFields map[string]string `json:"extra_fields"`
}

type VerifyResponse struct {
	ActionId string `json:"action_id"`
}

type ValidationTokenParams struct {
	TimeToLive  int `json:"time_to_live"`
	CountToLive int `json:"count_to_live"`
}
type ConfirmRequest struct {
	ConfirmationCode string                `json:"confirmation_code"`
	ActionId         string                `json:"action_id"`
	Params           ValidationTokenParams `json:"token"`
}

type ConfirmResponse struct {
	Type            string `json:"type"`
	Value           string `json:"value"`
	ValidationToken string `json:"validation_token"`
}

type ValidateRequest struct {
	Type            string `json:"type"`
	Value           string `json:"value"`
	ValidationToken string `json:"validation_token"`
}
