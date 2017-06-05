package transport

type Endpoint int

type HTTPEndpoint struct {
	URL    string
	Method string
	Params int
}
