package transport

import (
	"encoding/json"
	"fmt"
	"net/http"

	"time"

	"crypto/tls"

	"github.com/valyala/fasthttp"
	"gopkg.in/virgil.v4/errors"
)

type Endpoint int

// TransportClientDoer set a doer to Http Transport client
func TransportClientDoer(client Doer) func(t *TransportClient) {
	return func(t *TransportClient) {
		t.client = client
	}
}

// NewTransportClient create a new instance of HTTP Transport protocol for Virgil Client
// You can send nil for second paramter and by defaolt will be used http.Client
func NewTransportClient(endpoints map[Endpoint]*HTTPEndpoint, serviceURLs map[ServiceType]string, opts ...func(t *TransportClient)) *TransportClient {
	t := &TransportClient{
		endpoints:   endpoints,
		serviceURLs: serviceURLs,
		client: &fasthttp.Client{
			MaxIdleConnDuration: 1 * time.Hour,
			ReadTimeout:         1 * time.Minute,
			WriteTimeout:        1 * time.Minute,
			TLSConfig: &tls.Config{
				ClientSessionCache: tls.NewLRUClientSessionCache(0),
			},
		},
	}
	for _, option := range opts {
		option(t)
	}
	return t
}

// Doer is a simple interface for wrap request
type Doer interface {
	Do(*fasthttp.Request, *fasthttp.Response) error
}

// TransportClient is implementation for virgil client transport protocol
type TransportClient struct {
	endpoints   map[Endpoint]*HTTPEndpoint
	serviceURLs map[ServiceType]string
	client      Doer
	token       string
}

func (c *TransportClient) Call(endpoint Endpoint, payload interface{}, returnObj interface{}, params ...interface{}) error {

	var ep *HTTPEndpoint
	var baseURL string
	var ok bool

	if ep, ok = c.endpoints[endpoint]; !ok {
		return errors.Errorf("endpoint %d is not supported", endpoint)
	}

	if baseURL, ok = c.serviceURLs[ep.ServiceType]; !ok {
		return errors.Errorf("service %d is not supported", endpoint)
	}

	if len(params) != ep.Params {
		return errors.Errorf("expected %d params but got %d", ep.Params, len(params))
	}

	urlParams := make([]interface{}, 1)
	urlParams[0] = baseURL
	urlParams = append(urlParams, params...)

	baseURL = fmt.Sprintf(ep.URL, urlParams...)

	res, err := c.getBody(c.do(ep.Method, baseURL, payload))
	if err != nil {
		return err
	}
	err = json.Unmarshal(res, &returnObj)
	if err != nil {
		return errors.Wrap(err, "Cannot unmarshal response body")
	}
	return nil
}

func (c *TransportClient) SetToken(token string) {
	c.token = token
}

type responseError struct {
	Code int `json:"code"`
}

func (c *TransportClient) getBody(resp *fasthttp.Response, err error) ([]byte, error) {
	if resp == nil {
		return nil, errors.New("nil response")
	}

	if err != nil {
		return nil, errors.Wrap(err, "")
	}

	body := resp.Body()

	if resp.Header.StatusCode() == http.StatusNotFound {
		return nil, errors.Wrap(ErrNotFound, "")
	}

	if resp.Header.StatusCode() != http.StatusOK {
		verr := &responseError{}
		err = json.Unmarshal(body, verr)
		if err != nil {
			return nil, errors.Wrap(ErrByTransportCode(resp.Header.StatusCode(), string(body)), "")
		}
		return nil, errors.Wrap(GetErrByCode(resp.Header.StatusCode(), verr.Code), "")

	}
	return body, nil
}

func (c *TransportClient) do(method, url string, model interface{}) (*fasthttp.Response, error) {

	var req fasthttp.Request
	req.Header.SetMethod(method)
	req.Header.SetRequestURI(url)

	if model != nil {
		reqBody, err := json.Marshal(model)
		if err != nil {
			return nil, errors.Wrap(err, "Cannot marshal model")
		}
		req.SetBody(reqBody)
	}

	if len(c.token) > 0 {
		req.Header.Set("Authorization", fmt.Sprintf("VIRGIL %s", c.token))
	}

	var resp fasthttp.Response
	err := c.client.Do(&req, &resp)
	return &resp, err
}
