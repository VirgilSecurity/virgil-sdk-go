package pfs

import (
	"net/http"

	"gopkg.in/virgil.v4/transport"
)

const (
	CreateLTCCard = iota
	UploadOTCCards
	GetUserCredentials
	GetOTCCardCount
	URL = "https://pfs-stg.virgilsecurity.com"
)

var (
	Endpoints = map[transport.Endpoint]*transport.HTTPEndpoint{
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
