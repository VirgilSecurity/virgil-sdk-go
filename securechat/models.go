package securechat

import "gopkg.in/virgil.v5"

// Credentials represent user's cards needed to establish a PFS session

type Credentials struct {
	IdentityCard *virgil.Card
	LTC          *virgil.Card
	OTC          *virgil.Card
}

type Recipient struct {
	LTC  *virgil.Card
	OTCs []*virgil.Card
}

//easyjson:json
type CredentialsResponse struct {
	IdentityCard *virgil.CardResponse `json:"identity_card"`
	LTC          *virgil.CardResponse `json:"long_time_card"`
	OTC          *virgil.CardResponse `json:"one_time_card"`
}

//easyjson:json
type CredentialsRequest struct {
	CardIds []string `json:"identity_cards_ids"`
}

//easyjson:json
type CreateRecipientRequest struct {
	LTC  *virgil.SignableRequest   `json:"long_time_card"`
	OTCS []*virgil.SignableRequest `json:"one_time_cards"`
}

//easyjson:json
type CreateRecipientResponse struct {
	LTC  *virgil.CardResponse   `json:"long_time_card"`
	OTCS []*virgil.CardResponse `json:"one_time_cards"`
}

//easyjson:json
//contains both initial & following messages
type Message struct {
	ID         string `json:"initiator_ic_id,omitempty"`
	SessionId  []byte `json:"session_id,omitempty"`
	Eph        []byte `json:"eph,omitempty"`
	Signature  []byte `json:"sign,omitempty"`
	ICID       string `json:"responder_ic_id"`
	LTCID      string `json:"responder_ltc_id,omitempty"`
	OTCID      string `json:"responder_otc_id,omitempty"`
	Salt       []byte `json:"salt"`
	Ciphertext []byte `json:"ciphertext"`
}
