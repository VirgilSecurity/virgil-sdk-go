package cardsclient

import (
	"net/http"

	"gopkg.in/virgil.v4/transport"
)

const (
	AddRelation = iota
	DeleteRelation
	URL = "https://cards.virgilsecurity.com"
)

var (
	Endpoints = map[transport.Endpoint]*transport.HTTPEndpoint{
		AddRelation: {
			Method: http.MethodPost,
			URL:    "%s/v4/card/%s/collections/relations",
			Params: 1,
		},
		DeleteRelation: {
			Method: http.MethodDelete,
			URL:    "%s/v4/card/%s/collections/relations",
			Params: 1,
		}}
)
