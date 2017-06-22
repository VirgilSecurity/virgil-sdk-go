package securechat

import (
	"net/http"

	"gopkg.in/virgil.v4/transport"
)

const (
	CreateRecipient transport.Endpoint = iota
	CreateLTCCard
	UploadOTCCards
	GetUserCredentials
	GetOTCCardCount
	URL = "https://pfs-stg.virgilsecurity.com"
)

var (
	Endpoints = map[transport.Endpoint]*transport.HTTPEndpoint{
		CreateRecipient: {
			Method: http.MethodPut,
			URL:    "%s/v1/recipient/%s",
			Params: 1,
		},
		CreateLTCCard: {
			Method: http.MethodPost,
			URL:    "%s/v1/recipient/%s/actions/push-ltc",
			Params: 1,
		},
		UploadOTCCards: {
			Method: http.MethodPost,
			URL:    "%s/v1/recipient/%s/actions/push-otcs",
			Params: 1,
		},
		GetUserCredentials: {
			Method: http.MethodPost,
			URL:    "%s/v1/recipient/actions/search",
		},
		GetOTCCardCount: {
			Method: http.MethodPost,
			URL:    "%s/v1/recipient/%s/actions/count-otcs",
			Params: 1,
		},
	}
)
