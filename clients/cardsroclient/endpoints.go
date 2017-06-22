package cardsroclient

import (
	"net/http"

	"gopkg.in/virgil.v5/transport"
)

const (
	GetCard transport.Endpoint = iota
	SearchCards

	URL = "https://cards.virgilsecurity.com"
)

var (
	Endpoints = map[transport.Endpoint]*transport.HTTPEndpoint{
		GetCard: {
			Method: http.MethodGet,
			URL:    "%s/v4/card/%s",
			Params: 1,
		},
		SearchCards: {
			Method: http.MethodPost,
			URL:    "%s/v4/card/actions/search",
		},
	}
)
