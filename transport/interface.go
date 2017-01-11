package transport

import "gopkg.in/virgil.v4/transport/endpoints"

type Client interface {
	SetToken(token string)
	Call(endpoint endpoints.Endpoint, payload interface{}, returnObj interface{}, params ...interface{}) error
}
