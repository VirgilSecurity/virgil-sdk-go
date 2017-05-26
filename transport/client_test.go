package transport

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/valyala/fasthttp"
	"gopkg.in/virgil.v4/errors"
)

var services = map[ServiceType]string{
	0: "test url",
	1: "test ro url",
	2: "test ident url",
	3: "test vra url",
}

var endpoints = map[Endpoint]*HTTPEndpoint{
	0: {
		Method:      http.MethodGet,
		URL:         "%s/v4/card/%s",
		ServiceType: 0,
		Params:      1,
	},
}

func TestNewTransportClient_InitByDefault_DoerIsHttpClient(t *testing.T) {
	v := NewTransportClient(endpoints, services)
	assert.Equal(t, services[0], v.serviceURLs[0])
	assert.Equal(t, services[1], v.serviceURLs[1])
	assert.Equal(t, services[2], v.serviceURLs[2])
	assert.Equal(t, services[3], v.serviceURLs[3])
	assert.IsType(t, &fasthttp.Client{}, v.client)
}

type CustomClient struct {
	mock.Mock
}

func (c *CustomClient) Do(req *fasthttp.Request, resp *fasthttp.Response) (err error) {
	args := c.Called(req)
	if a, ok := args.Get(0).(func(response *fasthttp.Response)); ok {
		a(resp)
	}
	//resp, _ = args.Get(1).(*fasthttp.Response)
	err = args.Error(1)
	return
}

func TestNewTransportClient_InitWithCustomClient(t *testing.T) {
	v := NewTransportClient(endpoints, services, TransportClientDoer(&CustomClient{}))
	assert.IsType(t, &CustomClient{}, v.client)
}

func TestSetToken_Check(t *testing.T) {
	v := NewTransportClient(endpoints, services)
	v.token = ""
	v.SetToken("token")

	assert.Equal(t, "token", v.token)
}

func TestInvalidService_ReturnErr(t *testing.T) {
	c := NewTransportClient(nil, nil)
	err := c.Call(1000, nil, nil)
	assert.NotNil(t, err)
}

func TestInvalidParamsCount_ReturnErr(t *testing.T) {
	c := NewTransportClient(endpoints, services)
	err := c.Call(0, nil, nil, 0)
	assert.NotNil(t, err)
}

func makeFakeInvokes(c *TransportClient) []func() error {

	funcs := make([]func() error, 0)

	for e, eparams := range endpoints {
		funcs = append(funcs, func() error {
			err := c.Call(e, nil, nil, make([]interface{}, eparams.Params)...)
			return err
		})
	}

	return funcs

}

func Test_ClientReturnErr_ReturnErr(t *testing.T) {
	c := &CustomClient{}
	c.On("Do", mock.Anything).Return(nil, errors.New("format"))

	tc := NewTransportClient(endpoints, services, TransportClientDoer(c))

	tab := makeFakeInvokes(tc)
	for _, f := range tab {
		err := f()
		assert.NotNil(t, err)
	}
}

func Test_ClientReturnStatusNotOk_ReturnDecodedErr(t *testing.T) {

	c := &CustomClient{}

	fn := func(resp *fasthttp.Response) {
		resp.SetBody([]byte(`{"code":10000}`))
		resp.SetStatusCode(http.StatusBadRequest)
	}

	c.On("Do", mock.Anything).Return(fn, nil)

	tc := NewTransportClient(endpoints, services, TransportClientDoer(c))

	tab := makeFakeInvokes(tc)
	for _, f := range tab {
		err := f()
		assert.Error(t, err)
		sdkerr, ok := errors.ToSdkError(err)
		assert.True(t, ok)
		assert.Equal(t, sdkerr.ServiceError.ServiceErrorCode(), 10000)
	}
}

func Test_ClientReturnStatusNotOkAndBodyBroken_ReturnErr(t *testing.T) {
	resp := http.Response{
		Body:       ioutil.NopCloser(bytes.NewReader([]byte(`asdf;asdf`))),
		StatusCode: http.StatusBadRequest,
	}
	c := &CustomClient{}
	c.On("Do", mock.Anything).Return(&resp, nil)

	tc := NewTransportClient(endpoints, services, TransportClientDoer(c))
	tc.SetToken("token")

	tab := makeFakeInvokes(tc)
	for _, f := range tab {
		err := f()
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "unmarshal")
	}
}
