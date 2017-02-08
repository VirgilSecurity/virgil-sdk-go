package virgilhttp

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/valyala/fasthttp"
	"gopkg.in/virgil.v4/errors"
	"gopkg.in/virgil.v4/transport/endpoints"
)

func TestNewTransportClient_InitByDefault_DoerIsHttpClient(t *testing.T) {
	expectedService := "test url"
	expectedRoService := "test ro url"
	expectedIdentityService := "test ident url"
	expectedVRAService := "test vra url"
	v := NewTransportClient(expectedService, expectedRoService, expectedIdentityService, expectedVRAService)
	assert.Equal(t, expectedService, v.cardServiceURL)
	assert.Equal(t, expectedRoService, v.roCardServiceURL)
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
	v := NewTransportClient("test", "test", "test", "test", TransportClientDoer(&CustomClient{}))
	assert.IsType(t, &CustomClient{}, v.client)
}

func TestSetToken_Check(t *testing.T) {
	v := NewTransportClient("serviceURL", "roServiceURL", "identityUrl", "vraurl")
	v.token = ""
	v.SetToken("token")

	assert.Equal(t, "token", v.token)
}

func TestInvalidService_ReturnErr(t *testing.T) {
	c := NewTransportClient("serviceURL", "roServiceURL", "identityUrl", "vraurl")
	err := c.Call(1000, nil, nil)
	assert.NotNil(t, err)
}

func TestInvalidParamsCount_ReturnErr(t *testing.T) {
	c := NewTransportClient("serviceURL", "roServiceURL", "identityUrl", "vraurl")
	err := c.Call(endpoints.GetCard, nil, nil, 0)
	assert.NotNil(t, err)
}

func makeFakeInvokes(c *TransportClient) []func() error {

	funcs := make([]func() error, 0)

	for e, eparams := range HTTPEndpoints {
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

	tc := NewTransportClient("serviceURL", "roServiceURL", "identityUrl", "vraurl", TransportClientDoer(c))

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

	tc := NewTransportClient("serviceURL", "roServiceURL", "identityUrl", "vraurl", TransportClientDoer(c))

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

	tc := NewTransportClient("serviceURL", "roServiceURL", "identityUrl", "vraurl", TransportClientDoer(c))
	tc.SetToken("token")

	tab := makeFakeInvokes(tc)
	for _, f := range tab {
		err := f()
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "unmarshal")
	}
}
