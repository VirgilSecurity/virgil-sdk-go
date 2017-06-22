package virgilapi

import (
	"encoding/base64"
	"encoding/hex"

	"encoding/json"

	"gopkg.in/virgil.v5"
	"gopkg.in/virgil.v5/errors"
)

type CardManager interface {
	Get(id string) (*Card, error)
	Create(identity string, key *Key, customFields map[string]string) (*Card, error)
	CreateGlobal(identity string, key *Key) (*Card, error)
	Import(card string) (*Card, error)
	ConfirmIdentity(actionId string, confirmationCode string) (validationToken string, err error)
	Publish(card *Card) (*Card, error)
	PublishGlobal(card *Card, validationToken string) (*Card, error)
	Revoke(card *Card, reason virgil.Enum) error
	RevokeGlobal(card *Card, reason virgil.Enum, key *Key, validationToken string) error
	Find(identities ...string) (Cards, error)
	FindGlobal(identityType string, identities ...string) (Cards, error)
}

type cardManager struct {
	context *Context
}

func (c *cardManager) Get(id string) (*Card, error) {
	card, err := c.context.cardsROClient.GetCard(id)
	if err != nil {
		return nil, err
	}
	return &Card{
		Card:    card,
		context: c.context,
	}, nil
}

func (c *cardManager) Create(identity string, key *Key, customFields map[string]string) (*Card, error) {
	if key == nil || key.privateKey == nil || key.privateKey.Empty() {
		return nil, errors.New("nil key")
	}
	publicKey, err := key.privateKey.ExtractPublicKey()
	if err != nil {
		return nil, err
	}

	req, err := virgil.NewCreateCardRequest(identity, "unknown", publicKey, virgil.CardParams{Data: customFields})
	if err != nil {
		return nil, err
	}

	err = req.SelfSign(key.privateKey)
	if err != nil {
		return nil, err
	}
	return c.requestToCard(req)
}

func (c *cardManager) CreateGlobal(email string, key *Key) (*Card, error) {
	if key == nil || key.privateKey == nil || key.privateKey.Empty() {
		return nil, errors.New("nil key")
	}
	publicKey, err := key.privateKey.ExtractPublicKey()
	if err != nil {
		return nil, err
	}

	req, err := virgil.NewCreateCardRequest(email, "email", publicKey, virgil.CardParams{Scope: virgil.CardScope.Global})
	if err != nil {
		return nil, err
	}
	err = req.SelfSign(key.privateKey)
	if err != nil {
		return nil, err
	}

	return c.requestToCard(req)
}

func (c *cardManager) CreateApplicationCard(bundleName string, key *Key) (*Card, error) {
	if key == nil || key.privateKey == nil || key.privateKey.Empty() {
		return nil, errors.New("nil key")
	}
	publicKey, err := key.privateKey.ExtractPublicKey()
	if err != nil {
		return nil, err
	}

	req, err := virgil.NewCreateCardRequest(bundleName, "application", publicKey, virgil.CardParams{Scope: virgil.CardScope.Global})
	if err != nil {
		return nil, err
	}
	err = req.SelfSign(key.privateKey)
	if err != nil {
		return nil, err
	}

	return c.requestToCard(req)
}

// requestToCard converts createCardRequest to Card instance with context & model
func (c *cardManager) requestToCard(req *virgil.SignableRequest) (*Card, error) {
	id := hex.EncodeToString(virgil.Crypto().CalculateFingerprint(req.Snapshot))
	resp := &virgil.CardResponse{
		ID:       id,
		Snapshot: req.Snapshot,
		Meta: virgil.ResponseMeta{
			Signatures: req.Meta.Signatures,
		},
	}

	card, err := resp.ToCard()

	if err != nil {
		return nil, err
	}

	return &Card{
		context: c.context,
		Card:    card,
	}, nil
}

func (c *cardManager) Import(card string) (*Card, error) {
	data, err := base64.StdEncoding.DecodeString(card)
	if err != nil {
		return nil, err
	}

	var resp virgil.CardResponse
	err = json.Unmarshal(data, &resp)
	if err != nil {
		return nil, err
	}
	model, err := resp.ToCard()

	if err != nil {
		return nil, err
	}

	err = c.context.validator.Validate(model)

	if err != nil {
		return nil, errors.Wrap(err, "imported card validation failed")
	}

	return &Card{
		context: c.context,
		Card:    model,
	}, nil
}

func (c *cardManager) ConfirmIdentity(actionId string, confirmationCode string) (validationToken string, err error) {

	req := &virgil.ConfirmRequest{
		ActionId:         actionId,
		ConfirmationCode: confirmationCode,
		Params: virgil.ValidationTokenParams{
			CountToLive: 12,
			TimeToLive:  3600,
		},
	}
	resp, err := c.context.identityClient.ConfirmIdentity(req)
	if err != nil {
		return "", err
	}
	return resp.ValidationToken, nil
}

// Publish will sign request with app signature and try to publish it to the server
// The signature will be added to request
func (c *cardManager) Publish(card *Card) (*Card, error) {
	if c.context.appKey == nil || c.context.appKey.key == nil {
		return nil, errors.New("No app private key provided for request signing")
	}

	req, err := card.ToRequest()

	if err != nil {
		return nil, err
	}

	err = req.AuthoritySign(c.context.appKey.id, c.context.appKey.key)
	if err != nil {
		return nil, err
	}

	res, err := c.context.raClient.CreateCard(req)
	if err != nil {
		return nil, err
	}

	return &Card{
		context: c.context,
		Card:    res,
	}, nil
}

func (c *cardManager) PublishGlobal(card *Card, validationToken string) (*Card, error) {
	req, err := card.ToRequest()

	if err != nil {
		return nil, err
	}

	req.Meta.Validation = &virgil.ValidationInfo{}

	req.Meta.Validation.Token = validationToken
	res, err := c.context.raClient.CreateCard(req)
	if err != nil {
		return nil, err
	}

	return &Card{
		context: c.context,
		Card:    res,
	}, nil
}

func (c *cardManager) Revoke(card *Card, reason virgil.Enum) error {
	if c.context.appKey == nil || c.context.appKey.key == nil {
		return errors.New("No app private key provided for request signing")
	}

	req, err := virgil.NewRevokeCardRequest(card.ID, reason)
	if err != nil {
		return err
	}

	err = req.AuthoritySign(c.context.appKey.id, c.context.appKey.key)
	if err != nil {
		return err
	}

	return c.context.raClient.RevokeCard(req)
}

func (c *cardManager) RevokeGlobal(card *Card, reason virgil.Enum, signerKey *Key, validationToken string) error {

	req, err := virgil.NewRevokeCardRequest(card.ID, reason)
	if err != nil {
		return err
	}

	err = req.AuthoritySign(card.ID, signerKey.privateKey)
	if err != nil {
		return err
	}
	req.Meta.Validation = &virgil.ValidationInfo{}
	req.Meta.Validation.Token = validationToken

	return c.context.raClient.RevokeCard(req)
}

func (c *cardManager) Find(identities ...string) (Cards, error) {

	cards, err := c.context.cardsROClient.SearchCards(virgil.SearchCriteriaByIdentities(identities...))
	if err != nil {
		return nil, err
	}

	res := make([]*Card, len(cards))
	for i, card := range cards {
		res[i] = &Card{
			context: c.context,
			Card:    card,
		}
	}
	return res, nil
}

func (c *cardManager) FindGlobal(identityType string, identities ...string) (Cards, error) {

	cards, err := c.context.cardsROClient.SearchCards(&virgil.Criteria{
		IdentityType: identityType,
		Identities:   identities,
		Scope:        virgil.CardScope.Global,
	})
	if err != nil {
		return nil, err
	}

	res := make([]*Card, len(cards))
	for i, card := range cards {
		res[i] = &Card{
			context: c.context,
			Card:    card,
		}
	}
	return res, nil
}
