package pfs

import "gopkg.in/virgil.v4"

// Credentials represent user's cards needed to establish a PFS session
type Credentials struct {
	IdentityCard *virgil.Card
	LTC          *virgil.Card
	OTC          *virgil.Card
}

type CredentialsResponse struct {
	IdentityCard *virgil.CardResponse `json:"identity_card"`
	LTC          *virgil.CardResponse `json:"long_time_card"`
	OTC          *virgil.CardResponse `json:"one_time_card"`
}
