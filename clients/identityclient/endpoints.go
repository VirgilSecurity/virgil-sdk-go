package identityclient

import (
	"net/http"

	"gopkg.in/virgil.v4/transport"
)

const (
	VerifyIdentity transport.Endpoint = iota
	ConfirmIdentity
	ValidateIdentity

	URL = "https://identity.virgilsecurity.com"
)

var (
	Endpoints = map[transport.Endpoint]*transport.HTTPEndpoint{
		VerifyIdentity: {
			Method: http.MethodPost,
			URL:    "%s/v1/verify",
		},
		ConfirmIdentity: {
			Method: http.MethodPost,
			URL:    "%s/v1/confirm",
		},
		ValidateIdentity: {
			Method: http.MethodPost,
			URL:    "%s/v1/validate",
		},
	}
)
