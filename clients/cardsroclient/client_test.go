package cardsroclient

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"gopkg.in/virgil.v4"
	"gopkg.in/virgil.v4/clients"
	"gopkg.in/virgil.v4/errors"
	"gopkg.in/virgil.v4/transport"
	"gopkg.in/virgil.v4/virgilcrypto"
)

type FakeTransport struct {
	mock.Mock
}

func (t *FakeTransport) Call(endpoint transport.Endpoint, payload interface{}, returnObj interface{}, params ...interface{}) error {
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

func (t *FakeTransport) SetURL(url string) {
	t.Called(url)
}

type FakeValidator struct {
	mock.Mock
}

func (v *FakeValidator) Validate(c *virgil.Card) error {
	args := v.Called(c)
	return args.Error(0)
}

func (v *FakeValidator) ValidateExtra(c *virgil.Card, extraKeys map[string]virgilcrypto.PublicKey) error {
	args := v.Called(c, extraKeys)
	return args.Error(0)
}

func TestNewClient_InitByDefault_CheckStruct(t *testing.T) {
	c, _ := New("test")
	v, _ := virgil.MakeDefaultCardsValidator()

	assert.IsType(t, &transport.TransportClient{}, c.TransportClient)
	assert.Equal(t, v, c.CardsValidator)
}

func makeFakeTransport() *FakeTransport {
	tr := &FakeTransport{}
	tr.On("SetToken", mock.Anything).Return()
	//tr.On("Call", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, nil)
	return tr
}

func TestNewClient_OverwriteParams_CheckStruct(t *testing.T) {
	tr := makeFakeTransport()
	c, _ := New("test",
		clients.ClientTransport(tr),
		clients.ClientCardsValidator(&FakeValidator{}))

	assert.IsType(t, tr, c.TransportClient)
	assert.IsType(t, &FakeValidator{}, c.CardsValidator)

	tr.AssertCalled(t, "SetToken", "test")
}

func clientInvokes(tr transport.Client, v virgil.CardsValidator) []error {
	c, _ := New("test", clients.ClientTransport(tr), clients.ClientCardsValidator(v))
	return []error{
		func() error {
			_, err := c.GetCard("id")
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

func TestTable_UnmarshalSnapshotReturnErr_ReturnErr(t *testing.T) {
	resp := virgil.CardResponse{
		Snapshot: []byte("asdf;asd"),
		Meta: virgil.ResponseMeta{
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
	resp := virgil.CardResponse{
		Snapshot: []byte(`{"public_key":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUNvd0JRWURLMlZ3QXlFQTVGMVVSWk4yc2VWdVRvVlFLU0ZaOE9rRjA1MWpsVWpCdU05T1pTSGs9Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQ==","identity":"com.gibsonmic.ed255app","identity_type":"application","scope":"global"}`),
		Meta: virgil.ResponseMeta{
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
	resp := virgil.CardResponse{
		Snapshot: []byte(`{"public_key":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0NCk1Db3dCUVlESzJWd0F5RUE1RmxlNTFVUlpOMnNlVnVUb1ZRS1NGWjhPa0YwNTFqbFVqQnVNOU9aU0hrPQ0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t","identity":"com.gibsonmic.ed255app","identity_type":"application","scope":"global"}`),
		Meta: virgil.ResponseMeta{
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
	resp := virgil.CardResponse{
		ID:       "d32b745ec2f3ab47add5d89a18f41f5076dc93ccfb5f3c6a575aef58506a24ec",
		Snapshot: []byte(`{"public_key":"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0NCk1Db3dCUVlESzJWd0F5RUE1RmxlNTFVUlpOMnNlVnVUb1ZRS1NGWjhPa0YwNTFqbFVqQnVNOU9aU0hrPQ0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t","identity":"com.gibsonmic.ed255app","identity_type":"application","scope":"global"}`),
		Meta: virgil.ResponseMeta{
			Signatures: map[string][]byte{
				"asdf": []byte("asd"),
			},
		},
	}
	tr := makeFakeTransport()
	tr.On("Call", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&resp, nil)

	v := &FakeValidator{}
	v.On("Validate", mock.Anything).Return(nil)
	v.On("ValidateExtra", mock.Anything, mock.Anything).Return(nil)

	for _, err := range clientInvokes(tr, v) {
		assert.Nil(t, err)
	}
}

func makeFakeCardAndCardResponse() (*virgil.Card, *virgil.CardResponse) {
	pkbyte := []byte(`-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA5Fle51URZN2seVuToVQKSFZ8OkF051jlUjBuM9OZSHk=
-----END PUBLIC KEY-----`)
	pk, _ := virgil.Crypto().ImportPublicKey(pkbyte)
	r := virgil.CardModel{
		PublicKey:    pkbyte,
		Identity:     "com.gibsonmic.ed255app",
		IdentityType: "application",
		Scope:        virgil.CardScope.Global,
		Data: map[string]string{
			"Test": "Data",
		},
		DeviceInfo: virgil.DeviceInfo{
			Device:     "iphone7",
			DeviceName: "my iphone",
		},
	}
	b, _ := json.Marshal(r)
	card := &virgil.Card{
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
	resp := &virgil.CardResponse{
		ID:       card.ID,
		Snapshot: card.Snapshot,
		Meta: virgil.ResponseMeta{
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
	c, _ := New("accessToken", clients.ClientTransport(tr), clients.ClientCardsValidator(nil))
	card, _ := c.GetCard("dabc43986e8d9358ed7a9a2c57603397a561f92a29be0558254b3244ce9e72f5")

	assert.Equal(t, expected, card)
}

func TestSearchCards_EmptyIdentities_ReturntErr(t *testing.T) {
	c, _ := New("as")
	_, err := c.SearchCards(virgil.SearchCriteriaByAppBundle())

	assert.NotNil(t, err)
}

func TestSearchCards_CardsValidated_ReturnCard(t *testing.T) {
	expected, resp := makeFakeCardAndCardResponse()
	tr := makeFakeTransport()
	tr.On("Call", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return([]virgil.CardResponse{*resp}, nil)
	c, _ := New("accessToken", clients.ClientTransport(tr), clients.ClientCardsValidator(nil))
	card, _ := c.SearchCards(virgil.SearchCriteriaByAppBundle("bundle"))

	assert.Equal(t, expected, card[0])
}

func TestSearchCards_CheckPassedParameter(t *testing.T) {
	criteria := &virgil.Criteria{
		Identities: []string{
			"test1",
			"test2",
		},
		IdentityType: "app",
		Scope:        virgil.CardScope.Global,
	}
	tr := makeFakeTransport()

	tr.On("Call", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New("format"))
	c, _ := New("accessToken", clients.ClientTransport(tr), clients.ClientCardsValidator(nil))
	c.SearchCards(criteria)

	tr.AssertCalled(t, "Call", SearchCards, &virgil.Criteria{
		Identities: []string{
			"test1",
			"test2",
		},
		IdentityType: "app",
		Scope:        "global",
	}, mock.Anything)
}
