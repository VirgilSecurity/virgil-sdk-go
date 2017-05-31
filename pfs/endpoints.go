package pfs

import (
	"net/http"

	"gopkg.in/virgil.v4"
	. "gopkg.in/virgil.v4/transport"
)

const (
	PFSService ServiceType = 100
)

const (
	CreateLTCCard = 100
	UploadOTCCards
	GetUserCredentials
	GetOTCCardCount
)

var DefaultHTTPEndpoints map[Endpoint]*HTTPEndpoint = initEndpoints()

func initEndpoints() map[Endpoint]*HTTPEndpoint {
	res := map[Endpoint]*HTTPEndpoint{}
	for k, v := range virgil.DefaultHTTPEndpoints {
		res[k] = v
	}

	res[CreateLTCCard] = &HTTPEndpoint{
		Method:      http.MethodPost,
		URL:         "%s/v4/recipient/%s/actions/push-ltc",
		ServiceType: PFSService,
		Params:      1,
	}

	res[UploadOTCCards] = &HTTPEndpoint{
		Method:      http.MethodPost,
		URL:         "%s/v4/recipient/%s/actions/push-otcs",
		ServiceType: PFSService,
		Params:      1,
	}

	res[GetUserCredentials] = &HTTPEndpoint{
		Method:      http.MethodPost,
		URL:         "%s/v4/recipient/actions/search",
		ServiceType: PFSService,
	}

	res[GetOTCCardCount] = &HTTPEndpoint{
		Method:      http.MethodPost,
		URL:         "%s/v4/recipient/%s/actions/count-otcs",
		ServiceType: PFSService,
		Params:      1,
	}
	return res
}
