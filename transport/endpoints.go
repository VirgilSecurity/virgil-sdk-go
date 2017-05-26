package transport

type ServiceType int

type HTTPEndpoint struct {
	URL         string
	Method      string
	ServiceType ServiceType
	Params      int
}
