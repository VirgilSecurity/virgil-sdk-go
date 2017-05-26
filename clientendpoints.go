package virgil

import (
	"net/http"

	"gopkg.in/virgil.v4/transport"
)

const (
	GetCard transport.Endpoint = iota
	SearchCards
	CreateCard
	RevokeCard
	VerifyIdentity
	ConfirmIdentity
	ValidateIdentity
	AddRelation
	DeleteRelation
)

const (
	Cardservice transport.ServiceType = iota
	ROCardService
	IdentityService
	VRAService
)



var DefaultHTTPEndpoints = map[transport.Endpoint]*transport.HTTPEndpoint{
	GetCard: {
		Method:      http.MethodGet,
		URL:         "%s/v4/card/%s",
		ServiceType: ROCardService,
		Params:      1,
	},
	SearchCards: {
		Method:      http.MethodPost,
		URL:         "%s/v4/card/actions/search",
		ServiceType: ROCardService,
	},
	CreateCard: {
		Method:      http.MethodPost,
		URL:         "%s/v1/card",
		ServiceType: VRAService,
	},
	RevokeCard: {
		Method:      http.MethodDelete,
		URL:         "%s/v1/card/%s",
		ServiceType: VRAService,
		Params:      1,
	},
	VerifyIdentity: {
		Method:      http.MethodPost,
		URL:         "%s/v1/verify",
		ServiceType: IdentityService,
	},
	ConfirmIdentity: {
		Method:      http.MethodPost,
		URL:         "%s/v1/confirm",
		ServiceType: IdentityService,
	},
	ValidateIdentity: {
		Method:      http.MethodPost,
		URL:         "%s/v1/validate",
		ServiceType: IdentityService,
	},
	AddRelation: {
		Method:      http.MethodPost,
		URL:         "%s/v4/card/%s/collections/relations",
		ServiceType: Cardservice,
		Params:      1,
	},
	DeleteRelation: {
		Method:      http.MethodDelete,
		URL:         "%s/v4/card/%s/collections/relations",
		ServiceType: Cardservice,
		Params:      1,
	},
}
