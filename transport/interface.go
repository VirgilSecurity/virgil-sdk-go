package transport

type Client interface {
	SetToken(token string)
	Call(endpoint Endpoint, payload interface{}, returnObj interface{}, params ...interface{}) error
}
