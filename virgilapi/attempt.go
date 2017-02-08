package virgilapi

import "gopkg.in/virgil.v4"

type IdentityVerificationAttempt struct {
	context     *Context
	actionId    string
	TimeToLive  int
	CountToLive int
}

func (a *IdentityVerificationAttempt) Confirm(confirmationCode string) (string, error) {
	req := &virgil.ConfirmRequest{
		ActionId:         a.actionId,
		ConfirmationCode: confirmationCode,
		Params: virgil.ValidationTokenParams{
			CountToLive: a.CountToLive,
			TimeToLive:  a.TimeToLive,
		},
	}
	resp, err := a.context.client.ConfirmIdentity(req)
	if err != nil {
		return "", err
	}
	return resp.ValidationToken, nil
}
