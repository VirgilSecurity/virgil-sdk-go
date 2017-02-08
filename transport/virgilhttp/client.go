package virgilhttp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/valyala/fasthttp"
	"gopkg.in/virgil.v4/errors"
	"gopkg.in/virgil.v4/transport"
	"gopkg.in/virgil.v4/transport/endpoints"
	"time"
)

// TransportClientDoer set a doer to Http Transport client
func TransportClientDoer(client Doer) func(t *TransportClient) {
	return func(t *TransportClient) {
		t.client = client
	}
}

// NewTransportClient create a new instance of HTTP Transport protocol for Virgil Client
// You can send nil for second paramter and by defaolt will be used http.Client
func NewTransportClient(serviceURL string, roServiceURL string, identityServiceURL string, vraServiceURL string, opts ...func(t *TransportClient)) *TransportClient {
	t := &TransportClient{
		cardServiceURL:     strings.TrimRight(serviceURL, "/"),
		roCardServiceURL:   strings.TrimRight(roServiceURL, "/"),
		identityServiceURL: strings.TrimRight(identityServiceURL, "/"),
		vraServiceURL:      strings.TrimRight(vraServiceURL, "/"),
		client:             &fasthttp.Client{MaxIdleConnDuration: 24 * time.Hour},
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
	cardServiceURL     string
	roCardServiceURL   string
	identityServiceURL string
	vraServiceURL      string
	client             Doer
	token              string
}

func (c *TransportClient) Call(endpoint endpoints.Endpoint, payload interface{}, returnObj interface{}, params ...interface{}) error {

	var ep *HTTPEndpoint

	if e, ok := HTTPEndpoints[endpoint]; !ok {
		return errors.Errorf("endpoint %d is not supported", endpoint)
	} else {
		ep = e
	}

	url, err := c.ToServiceURL(ep.ServiceType)
	if err != nil {
		return err
	}
	if len(params) != ep.Params {
		return errors.Errorf("expected %d params but got %d", ep.Params, len(params))
	}

	urlParams := make([]interface{}, 1)
	urlParams[0] = url
	urlParams = append(urlParams, params...)

	url = fmt.Sprintf(ep.URL, urlParams...)

	res, err := c.getBody(c.do(ep.Method, url, payload))
	if err != nil {
		return err
	}
	err = json.Unmarshal(res, &returnObj)
	if err != nil {
		return errors.Wrap(err, "Cannot unmarshal response body")
	}
	return nil
}

func (c *TransportClient) ToServiceURL(serviceType ServiceType) (string, error) {
	switch serviceType {
	case Cardservice:
		return c.cardServiceURL, nil
	case ROCardService:
		return c.roCardServiceURL, nil
	case IdentityService:
		return c.identityServiceURL, nil
	case VRAService:
		return c.vraServiceURL, nil

	default:
		return "", errors.Errorf("service %d not supported", serviceType)

	}
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
		return nil, errors.Wrap(transport.ErrNotFound, "")
	}

	if resp.Header.StatusCode() != http.StatusOK {
		verr := &responseError{}
		err = json.Unmarshal(body, verr)
		if err != nil {
			return nil, errors.Wrap(transport.ErrByTransportCode(resp.Header.StatusCode(), string(body)), "")
		}
		return nil, errors.Wrap(transport.GetErrByCode(resp.Header.StatusCode(), verr.Code), "")

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
