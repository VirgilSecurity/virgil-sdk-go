package virgil

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"gopkg.in/virgil.v4/errors"
	"gopkg.in/virgil.v4/transport"
	"gopkg.in/virgil.v4/transport/endpoints"
	"gopkg.in/virgil.v4/transport/virgilhttp"
)

type FakeTransport struct {
	mock.Mock
}

func (t *FakeTransport) Call(endpoint endpoints.Endpoint, payload interface{}, returnObj interface{}, params ...interface{}) error {
	argz := make([]interface{}, 3)
	argz[0] = endpoint
	argz[1] = payload
	argz[2] = returnObj

	argz = append(argz, params...)
	args := t.Called(argz...)

	d, _ := json.Marshal(args.Get(0))
	json.Unmarshal(d, returnObj)

	return args.Error(1)
}

func (t *FakeTransport) SetToken(token string) {
	t.Called(token)
}

type FakeValidator struct {
	mock.Mock
}

func (v *FakeValidator) Validate(c *Card) (bool, error) {
	args := v.Called(c)
	return args.Bool(0), args.Error(1)
}

func TestNewClient_InitByDefault_CheckStruct(t *testing.T) {
	c, _ := NewClient("test")
	v, _ := makeDefaultCardsValidator()

	assert.IsType(t, &virgilhttp.TransportClient{}, c.transportClient)
	assert.Equal(t, v, c.cardsValidator)
}

func makeFakeTransport() *FakeTransport {
	tr := &FakeTransport{}
	tr.On("SetToken", mock.Anything).Return()
	//tr.On("Call", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, nil)
	return tr
}

func TestNewClient_OverwriteParams_CheckStruct(t *testing.T) {
	tr := makeFakeTransport()
	c, _ := NewClient("test",
		ClientTransport(tr),
		ClientCardsValidator(&FakeValidator{}))

	assert.IsType(t, tr, c.transportClient)
	assert.IsType(t, &FakeValidator{}, c.cardsValidator)

	tr.AssertCalled(t, "SetToken", "test")
}

func clientInvokes(tr transport.Client, v CardsValidator) []error {
	c, _ := NewClient("test", ClientTransport(tr), ClientCardsValidator(v))
	return []error{
		func() error {
			_, err := c.GetCard("id")
			return err
		}(),
		func() error {
			_, err := c.CreateCard(&SignableRequest{})
			return err
		}(),
		//func() error {
		//	_, err := c.SearchCards(Criteria{
		//		Identities: []string{
		//			"test",
		//		},
		//	})
		//	return err
		//}(),
	}
}

func TestTable_TransportClientReturnErr_ReturnErr(t *testing.T) {
	tr := makeFakeTransport()
	tr.On("Call", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New("format"))

	for _, err := range clientInvokes(tr, nil) {
		assert.NotNil(t, err)
	}

	c, _ := NewClient("accessToken", ClientTransport(tr))
	assert.NotNil(t, c.RevokeCard(&SignableRequest{}))
}

func TestTable_UnmarshalSnapshotReturnErr_ReturnErr(t *testing.T) {
	resp := CardResponse{
		Snapshot: []byte("asdf;asd"),
		Meta: ResponseMeta{
			Signatures: map[string][]byte{
				"asdf": []byte("asd"),
			},
		},
	}
	tr := makeFakeTransport()
	tr.On("Call", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&resp, nil)

	for _, err := range clientInvokes(tr, nil) {
		assert.NotNil(t, err)
	}
}

func TestTable_PublicKeyBroken_ReturnErr(t *testing.T) {
	resp := CardResponse{
		Snapshot: []byte(`{"public_key":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUNvd0JRWURLMlZ3QXlFQTVGMVVSWk4yc2VWdVRvVlFLU0ZaOE9rRjA1MWpsVWpCdU05T1pTSGs9Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQ==","identity":"com.gibsonmic.ed255app","identity_type":"application","scope":"global"}`),
		Meta: ResponseMeta{
			Signatures: map[string][]byte{
				"asdf": []byte("asd"),
			},
		},
	}
	tr := makeFakeTransport()
	tr.On("Call", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&resp, nil)

	for _, err := range clientInvokes(tr, nil) {
		assert.NotNil(t, err)
	}
}

func TestTable_CardNotValidated_ReturnErr(t *testing.T) {
	resp := CardResponse{
		Snapshot: []byte(`{"public_key":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0NCk1Db3dCUVlESzJWd0F5RUE1RmxlNTFVUlpOMnNlVnVUb1ZRS1NGWjhPa0YwNTFqbFVqQnVNOU9aU0hrPQ0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t","identity":"com.gibsonmic.ed255app","identity_type":"application","scope":"global"}`),
		Meta: ResponseMeta{
			Signatures: map[string][]byte{
				"asdf": []byte("asd"),
			},
		},
	}
	tr := makeFakeTransport()
	tr.On("Call", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&resp, nil)

	v := &FakeValidator{}
	v.On("Validate", mock.Anything).Return(false, errors.New("ERROR"))

	for _, err := range clientInvokes(tr, v) {
		assert.NotNil(t, err)
	}
}

func TestTable_CardValidated_ReturnNilErr(t *testing.T) {
	resp := CardResponse{
		ID:       "d32b745ec2f3ab47add5d89a18f41f5076dc93ccfb5f3c6a575aef58506a24ec",
		Snapshot: []byte(`{"public_key":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0NCk1Db3dCUVlESzJWd0F5RUE1RmxlNTFVUlpOMnNlVnVUb1ZRS1NGWjhPa0YwNTFqbFVqQnVNOU9aU0hrPQ0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t","identity":"com.gibsonmic.ed255app","identity_type":"application","scope":"global"}`),
		Meta: ResponseMeta{
			Signatures: map[string][]byte{
				"asdf": []byte("asd"),
			},
		},
	}
	tr := makeFakeTransport()
	tr.On("Call", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&resp, nil)

	v := &FakeValidator{}
	v.On("Validate", mock.Anything).Return(true, nil)

	for _, err := range clientInvokes(tr, v) {
		assert.Nil(t, err)
	}
}

func makeFakeCardAndCardResponse() (*Card, *CardResponse) {
	pkbyte := []byte(`-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA5Fle51URZN2seVuToVQKSFZ8OkF051jlUjBuM9OZSHk=
-----END PUBLIC KEY-----`)
	pk, _ := Crypto().ImportPublicKey(pkbyte)
	r := CardModel{
		PublicKey:    pkbyte,
		Identity:     "com.gibsonmic.ed255app",
		IdentityType: "application",
		Scope:        CardScope.Global,
		Data: map[string]string{
			"Test": "Data",
		},
		DeviceInfo: DeviceInfo{
			Device:     "iphone7",
			DeviceName: "my iphone",
		},
	}
	b, _ := json.Marshal(r)
	card := &Card{
		ID:           "dabc43986e8d9358ed7a9a2c57603397a561f92a29be0558254b3244ce9e72f5",
		Snapshot:     b,
		PublicKey:    pk,
		Identity:     r.Identity,
		IdentityType: r.IdentityType,
		Scope:        r.Scope,
		Data:         r.Data,
		DeviceInfo:   r.DeviceInfo,
		CardVersion:  "4.0",
		CreatedAt:    "today",
		Signatures: map[string][]byte{
			"sign": []byte("sign data"),
		},
	}
	resp := &CardResponse{
		ID:       card.ID,
		Snapshot: card.Snapshot,
		Meta: ResponseMeta{
			Signatures:  card.Signatures,
			CardVersion: card.CardVersion,
			CreatedAt:   card.CreatedAt,
		},
	}
	return card, resp
}

func TestGetCard_ReturnCard(t *testing.T) {
	expected, resp := makeFakeCardAndCardResponse()
	tr := makeFakeTransport()
	tr.On("Call", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(resp, nil)
	c, _ := NewClient("accessToken", ClientTransport(tr), ClientCardsValidator(nil))
	card, _ := c.GetCard("dabc43986e8d9358ed7a9a2c57603397a561f92a29be0558254b3244ce9e72f5")

	assert.Equal(t, expected, card)
}

func TestSearchCards_EmptyIdentities_ReturntErr(t *testing.T) {
	c, _ := NewClient("as")
	_, err := c.SearchCards(SearchCriteriaByAppBundle())

	assert.NotNil(t, err)
}

func TestSearchCards_CardsValidated_ReturnCard(t *testing.T) {
	expected, resp := makeFakeCardAndCardResponse()
	tr := makeFakeTransport()
	tr.On("Call", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return([]CardResponse{*resp}, nil)
	c, _ := NewClient("accessToken", ClientTransport(tr), ClientCardsValidator(nil))
	card, _ := c.SearchCards(SearchCriteriaByAppBundle("bundle"))

	assert.Equal(t, expected, card[0])
}

func TestSearchCards_CheckPassedParameter(t *testing.T) {
	criteria := &Criteria{
		Identities: []string{
			"test1",
			"test2",
		},
		IdentityType: "app",
		Scope:        CardScope.Global,
	}
	tr := makeFakeTransport()

	tr.On("Call", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New("format"))
	c, _ := NewClient("accessToken", ClientTransport(tr), ClientCardsValidator(nil))
	c.SearchCards(criteria)

	tr.AssertCalled(t, "Call", endpoints.SearchCards, &Criteria{
		Identities: []string{
			"test1",
			"test2",
		},
		IdentityType: "app",
		Scope:        "global",
	}, mock.Anything)
}

func TestCreateCard_CardsValidated_ReturnCard(t *testing.T) {
	expected, resp := makeFakeCardAndCardResponse()
	tr := makeFakeTransport()
	tr.On("Call", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(resp, nil)
	c, _ := NewClient("accessToken", ClientTransport(tr), ClientCardsValidator(nil))
	card, _ := c.CreateCard(&SignableRequest{})

	assert.Equal(t, expected, card)
}

func TestCreateCard_CheckPassedParameter(t *testing.T) {
	pkbyte := []byte(`-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA5Fle51URZN2seVuToVQKSFZ8OkF051jlUjBuM9OZSHk=
-----END PUBLIC KEY-----`)
	pk, _ := Crypto().ImportPublicKey(pkbyte)
	sr, _ := NewCreateCardRequest("identity", "identityType", pk, CardParams{
		Scope: CardScope.Application,
		Data: map[string]string{
			"data": "value",
		},
		DeviceInfo: DeviceInfo{
			Device:     "device",
			DeviceName: "deviceName",
		},
	})
	sr.AppendSignature("cardId", []byte("signature"))

	tr := makeFakeTransport()
	tr.On("Call", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New("format"))
	c, _ := NewClient("accessToken", ClientTransport(tr), ClientCardsValidator(nil))
	c.CreateCard(sr)

	tr.AssertCalled(t, "Call", endpoints.CreateCard, &SignableRequest{
		Snapshot: sr.Snapshot,
		Meta: RequestMeta{
			Signatures: sr.Meta.Signatures,
		},
	}, mock.Anything)
}

func TestRevokeCard_ReturnNil(t *testing.T) {
	tr := makeFakeTransport()
	r, _ := NewRevokeCardRequest("id", RevocationReason.Compromised)

	tr.On("Call", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, nil)
	c, _ := NewClient("accessToken", ClientTransport(tr))

	err := c.RevokeCard(r)

	assert.Nil(t, err)
}

func TestRevokeCard_CheckPassedParameter(t *testing.T) {
	tr := makeFakeTransport()
	r, _ := NewRevokeCardRequest("id", RevocationReason.Compromised)
	r.AppendSignature("cardId", []byte("signature"))

	tr.On("Call", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, nil)
	c, _ := NewClient("accessToken", ClientTransport(tr))

	c.RevokeCard(r)

	tr.AssertCalled(t, "Call", endpoints.RevokeCard, &SignableRequest{
		Snapshot: r.Snapshot,
		Meta: RequestMeta{
			Signatures: r.Meta.Signatures,
		},
	}, nil, "id")
}
