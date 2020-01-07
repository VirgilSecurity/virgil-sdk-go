package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"time"

	"github.com/cenkalti/backoff/v4"

	"github.com/VirgilSecurity/virgil-sdk-go"
	"github.com/VirgilSecurity/virgil-sdk-go/errors"
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
		defaultCodec: JSONCodec{},
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
	r.Header.Set(virgilAgentHeader, s.options.virgilAgent)

	resp, err := s.retry(ctx, r)
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

func (s *Client) retry(ctx context.Context, r *http.Request) (*http.Response, error) {
	var result *http.Response

	operation := func() error {
		cr := httpClone(r)
		resp, err := s.options.httpClient.Do(cr.WithContext(ctx))
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

// copy methods from net/http 1.13

// Clone returns a deep copy of r with its context changed to ctx.
// The provided ctx must be non-nil.
//
// For an outgoing client request, the context controls the entire
// lifetime of a request and its response: obtaining a connection,
// sending the request, and reading the response headers and body.
func httpClone(r *http.Request) *http.Request {
	r2 := new(http.Request)
	*r2 = *r
	r2.URL = cloneURL(r.URL)
	if r.Header != nil {
		r2.Header = cloneHeader(r.Header)
	}
	if r.Trailer != nil {
		r2.Trailer = cloneHeader(r.Trailer)
	}
	if s := r.TransferEncoding; s != nil {
		s2 := make([]string, len(s))
		copy(s2, s)
		r2.TransferEncoding = s
	}
	r2.Form = cloneURLValues(r.Form)
	r2.PostForm = cloneURLValues(r.PostForm)
	r2.MultipartForm = cloneMultipartForm(r.MultipartForm)
	return r2
}

func cloneURL(u *url.URL) *url.URL {
	if u == nil {
		return nil
	}
	u2 := new(url.URL)
	*u2 = *u
	if u.User != nil {
		u2.User = new(url.Userinfo)
		*u2.User = *u.User
	}
	return u2
}

func cloneURLValues(v url.Values) url.Values {
	if v == nil {
		return nil
	}
	// http.Header and url.Values have the same representation, so temporarily
	// treat it like http.Header, which does have a clone:
	return url.Values(cloneHeader(http.Header(v)))
}

func cloneMultipartForm(f *multipart.Form) *multipart.Form {
	if f == nil {
		return nil
	}
	f2 := &multipart.Form{
		Value: (map[string][]string)(cloneHeader(http.Header(f.Value))),
	}
	if f.File != nil {
		m := make(map[string][]*multipart.FileHeader)
		for k, vv := range f.File {
			vv2 := make([]*multipart.FileHeader, len(vv))
			for i, v := range vv {
				vv2[i] = cloneMultipartFileHeader(v)
			}
			m[k] = vv2
		}
		f2.File = m
	}
	return f2
}

func cloneMultipartFileHeader(fh *multipart.FileHeader) *multipart.FileHeader {
	if fh == nil {
		return nil
	}
	fh2 := new(multipart.FileHeader)
	*fh2 = *fh
	fh2.Header = textproto.MIMEHeader(cloneHeader(http.Header(fh.Header)))
	return fh2
}

func cloneHeader(h http.Header) http.Header {
	if h == nil {
		return nil
	}

	// Find total number of values.
	nv := 0
	for _, vv := range h {
		nv += len(vv)
	}
	sv := make([]string, nv) // shared backing array for headers' values
	h2 := make(http.Header, len(h))
	for k, vv := range h {
		n := copy(sv, vv)
		h2[k] = sv[:n:n]
		sv = sv[n:]
	}
	return h2
}
