package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/cenkalti/backoff/v4"

	"github.com/VirgilSecurity/virgil-sdk-go/v6"
	"github.com/VirgilSecurity/virgil-sdk-go/v6/errors"
)

var virgilAgentHeader = "Virgil-Agent"

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
	virgilAgent  string
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

func VirgilProduct(product string) Option {
	return func(o *options) {
		o.virgilAgent = virgil.MakeVirgilAgent(product)
	}
}

func NewClient(address string, opts ...Option) *Client {
	options := &options{
		httpClient:   DefaultHTTPClient,
		errorHandler: DefaultErrorHandler,
		defaultCodec: &JSONCodec{},
		virgilAgent:  virgil.MakeVirgilAgent("unknown"),
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
	req.Header.Set("Accept", cd.Name())
	req.Header.Set(virgilAgentHeader, s.options.virgilAgent)

	resp, err := s.retry(ctx, req.Method, req.Endpoint, req.Header, reqBody)
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

func (s *Client) retry(ctx context.Context, method string, endpoint string, header http.Header, reqBody []byte) (*http.Response, error) {
	var result *http.Response

	operation := func() error {
		r, err := http.NewRequest(method, s.address+endpoint, bytes.NewReader(reqBody))
		if err != nil {
			return err
		}
		r.Header = header
		resp, err := s.options.httpClient.Do(r.WithContext(ctx))
		if err != nil {
			return err
		}

		// catch 5xx so retry
		if resp.StatusCode/100 == 5 {
			// nolint: errcheck
			defer resp.Body.Close()

			respBody, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return err
			}

			result := &Response{
				StatusCode: resp.StatusCode,
				Header:     resp.Header,
				Body:       respBody,
				cd:         s.options.defaultCodec,
			}
			if err = s.options.errorHandler(result); err == nil {
				panic("HTTP client error handler should return non nil error")
			}
			return err
		}
		result = resp
		return nil
	}

	exp := backoff.NewExponentialBackOff()
	exp.InitialInterval = 200 * time.Millisecond
	exp.RandomizationFactor = 0.5
	exp.MaxElapsedTime = 4 * time.Second
	bs := backoff.WithMaxRetries(exp, 5)

	err := backoff.RetryNotify(operation, bs, func(err error, d time.Duration) {

	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

var DefaultHTTPClient = &http.Client{
	Timeout: time.Second * 10,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			ClientSessionCache: tls.NewLRUClientSessionCache(64),
		},
		TLSHandshakeTimeout: 5 * time.Second,
		MaxIdleConnsPerHost: 64,
	},
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

	apiErr := &errors.VirgilAPIError{}
	if len(resp.Body) != 0 {
		if err := resp.Unmarshal(apiErr); err != nil {
			return &Error{
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

func (e *Error) Error() string {
	return fmt.Sprintf("http client error {status code: %d message: %s}: %v", e.StatusCode, e.Message, e.ierr)
}

func (e *Error) Unwrap() error {
	return e.ierr
}

func (e *Error) Cause() error {
	return e.ierr
}
