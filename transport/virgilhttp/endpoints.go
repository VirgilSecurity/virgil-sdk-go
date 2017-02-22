package virgilhttp

import (
	"net/http"

	. "gopkg.in/virgil.v4/transport/endpoints"
)

type ServiceType int

const (
	Cardservice ServiceType = iota
	ROCardService
	IdentityService
	VRAService
)

type HTTPEndpoint struct {
	URL         string
	Method      string
	ServiceType ServiceType
	Params      int
}

var HTTPEndpoints = map[Endpoint]*HTTPEndpoint{
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
