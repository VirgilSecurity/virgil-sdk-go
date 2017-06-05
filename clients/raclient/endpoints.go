package raclient

import (
	"net/http"

	"gopkg.in/virgil.v4/transport"
)

const (
	CreateCard = iota
	RevokeCard

	URL = "https://ra.virgilsecurity.com"
)

var (
	Endpoints = map[transport.Endpoint]*transport.HTTPEndpoint{
		CreateCard: {
			Method: http.MethodPost,
			URL:    "%s/v1/card",
		},
		RevokeCard: {
			Method: http.MethodDelete,
			URL:    "%s/v1/card/%s",
			Params: 1,
		}}
)
