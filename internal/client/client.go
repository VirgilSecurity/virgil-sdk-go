package client

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/VirgilSecurity/virgil-sdk-go"
	"github.com/VirgilSecurity/virgil-sdk-go/errors"
)

//
// Codec is interface for marshal/unmarshal
//
type Codec interface {
	Marshal(obj interface{}) (body []byte, err error)
	Unmarshal(data []byte, obj interface{}) error
	Name() string
}

type Response struct {
	StatusCode int
	Header     http.Header
	Body       []byte
	cd         Codec
}

func (r *Response) Unmarshal(v interface{}) error {
	return r.cd.Unmarshal(r.Body, v)
}

type Request struct {
	Method   string
	Endpoint string
	Header   http.Header
	Payload  interface{}
}

type Option func(o *options)

type options struct {
	httpClient   *http.Client
	errorHandler func(resp *Response) error
	defaultCodec Codec
}

func HTTPClient(c *http.Client) Option {
	return func(o *options) {
		o.httpClient = c
	}
}

func ErrorHandler(h func(resp *Response) error) Option {
	return func(o *options) {
		o.errorHandler = h
	}
}

func DefaultCodec(c Codec) Option {
	return func(o *options) {
		o.defaultCodec = c
	}
}

func NewClient(address string, opts ...Option) *Client {
	options := &options{
		httpClient:   &http.Client{},
		errorHandler: DefaultErrorHandler,
		defaultCodec: JSONCodec{},
	}

	for _, o := range opts {
		o(options)
	}
	Client := &Client{
		options: options,
		address: address,
	}

	return Client
}

type Client struct {
	address string
	options *options
}

func (s *Client) Send(ctx context.Context, req *Request) (result *Response, err error) {
	if req.Header == nil {
		req.Header = http.Header{}
	}

	cd := s.options.defaultCodec

	var reqBody []byte
	if req.Payload != nil {
		req.Header.Set("Content-Type", cd.Name())

		if reqBody, err = cd.Marshal(req.Payload); err != nil {
			return nil, err
		}
	}
	r, err := http.NewRequest(req.Method, s.address+req.Endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}

	for k, v := range req.Header {
		if len(v) != 0 {
			r.Header.Set(k, v[0])
		}
	}

	r.Header.Set("Accept", cd.Name())
	r.Header.Set("Virgil-Agent", virgil.GetAgentHeader())

	resp, err := s.options.httpClient.Do(r.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	// nolint: errcheck
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	result = &Response{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       respBody,
		cd:         cd,
	}
	if result.StatusCode/100 == 2 { // 2xx
		return result, nil
	}

	if err = s.options.errorHandler(result); err == nil {
		panic("HTTP client error handler should return non nil error")
	}
	return nil, err
}

func DefaultErrorHandler(resp *Response) error {
	if len(resp.Body) == 0 {
		if resp.StatusCode == http.StatusNotFound {
			return errors.ErrEntityNotFound
		}
		if resp.StatusCode/100 == 5 { // 5xx
			return errors.ErrInternalServerError
		}
	}

	var apiErr errors.VirgilAPIError
	if len(resp.Body) != 0 {
		if err := resp.Unmarshal(&apiErr); err != nil {
			return Error{
				StatusCode: resp.StatusCode,
				ierr:       err,
			}
		}
	}
	return apiErr
}

type Error struct {
	StatusCode int
	Message    string
	ierr       error
}

func (e Error) Error() string {
	return fmt.Sprintf("http client error {status code: %d message: %s}: %v", e.StatusCode, e.Message, e.ierr)
}

func (e Error) Unwrap() error {
	return e.ierr
}

func (e Error) Cause() error {
	return e.ierr
}
