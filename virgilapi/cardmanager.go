package virgilapi

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"gopkg.in/virgil.v4"
	"gopkg.in/virgil.v4/errors"
	"gopkg.in/virgil.v4/virgilcrypto"
)

type CardManager interface {
	Get(id string) (*Card, error)
	Create(identity string, identityType string, key *Key) (*Card, error)
	CreateGlobal(identity string, identityType string, key *Key) (*Card, error)
	Export(card *Card) (string, error)
	Import(card string) (*Card, error)
	VerifyIdentity(card *Card) (actionId string, err error)
	ConfirmIdentity(actionId string, confirmationCode string) (validationToken string, err error)
	Publish(card *Card) (*Card, error)
	PublishGlobal(card *Card, validationToken string) (*Card, error)
	Revoke(card *Card, reason virgil.Enum) error
	RevokeGlobal(card *Card, reason virgil.Enum, key *Key, validationToken string) error
}

type cardManager struct {
	Context *Context
}

func (c *cardManager) Get(id string) (*Card, error) {
	card, err := c.Context.client.GetCard(id)
	if err != nil {
		return nil, err
	}
	return &Card{
		Model:   card,
		Context: c.Context,
	}, nil
}

func (c *cardManager) Create(identity string, identityType string, key *Key) (*Card, error) {
	publicKey, err := key.PrivateKey.ExtractPublicKey()
	if err != nil {
		return nil, err
	}

	req, err := virgil.NewCreateCardRequest(identity, identityType, publicKey, virgil.CardParams{})
	if err != nil {
		return nil, err
	}

	return c.requestToCard(req, key.PrivateKey)
}

func (c *cardManager) CreateGlobal(identity string, identityType string, key *Key) (*Card, error) {
	publicKey, err := key.PrivateKey.ExtractPublicKey()
	if err != nil {
		return nil, err
	}

	req, err := virgil.NewCreateCardRequest(identity, identityType, publicKey, virgil.CardParams{Scope: virgil.CardScope.Global})
	if err != nil {
		return nil, err
	}

	return c.requestToCard(req, key.PrivateKey)
}

// requestToCard converts createCardRequest to Card instance with context & model
func (c *cardManager) requestToCard(req *virgil.SignableRequest, key virgilcrypto.PrivateKey) (*Card, error) {
	signer := &virgil.RequestSigner{}
	err := signer.SelfSign(req, key)
	if err != nil {
		return nil, err
	}

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
		Context: c.Context,
		Model:   card,
	}, nil
}

func (c *cardManager) Export(card *Card) (string, error) {
	req, err := card.Model.ToRequest()
	if err != nil {
		return "", err
	}
	data, err := req.Export()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

func (c *cardManager) Import(card string) (*Card, error) {
	data, err := base64.StdEncoding.DecodeString(card)
	if err != nil {
		return nil, err
	}

	req, err := virgil.ImportCreateCardRequest(data)
	if err != nil {
		return nil, err
	}
	id := hex.EncodeToString(virgil.Crypto().CalculateFingerprint(req.Snapshot))
	resp := &virgil.CardResponse{
		ID:       id,
		Snapshot: req.Snapshot,
		Meta: virgil.ResponseMeta{
			Signatures: req.Meta.Signatures,
		},
	}

	model, err := resp.ToCard()

	if err != nil {
		return nil, err
	}

	return &Card{
		Context: c.Context,
		Model:   model,
	}, nil
}

func (c *cardManager) VerifyIdentity(card *Card) (actionId string, err error) {

	createReq := &virgil.CardModel{}
	err = json.Unmarshal(card.Model.Snapshot, createReq)
	if err != nil {
		return "", errors.Wrap(err, "Cannot unwrap request snapshot")
	}

	req := &virgil.VerifyRequest{
		Type:  createReq.IdentityType,
		Value: createReq.Identity,
	}

	resp, err := c.Context.client.VerifyIdentity(req)
	if err != nil {
		return "", err
	}
	return resp.ActionId, nil
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
	resp, err := c.Context.client.ConfirmIdentity(req)
	if err != nil {
		return "", err
	}
	return resp.ValidationToken, nil
}

// Publish will sign request with app signature and try to publish it to the server
// The signature will be added to request
func (c *cardManager) Publish(card *Card) (*Card, error) {
	pk := c.Context.Config.Credentials.Key
	if pk == nil || pk.PrivateKey == nil {
		return nil, errors.New("No app private key provided for request signing")
	}

	signer := &virgil.RequestSigner{}

	req, err := card.Model.ToRequest()

	if err != nil {
		return nil, err
	}

	err = signer.AuthoritySign(req, c.Context.Config.Credentials.AppId, pk.PrivateKey)
	if err != nil {
		return nil, err
	}

	res, err := c.Context.client.CreateCard(req)
	if err != nil {
		return nil, err
	}

	return &Card{
		Context: c.Context,
		Model:   res,
	}, nil
}

func (c *cardManager) PublishGlobal(card *Card, validationToken string) (*Card, error) {
	req, err := card.Model.ToRequest()

	if err != nil {
		return nil, err
	}

	req.Meta.Validation = &virgil.ValidationInfo{}

	req.Meta.Validation.Token = validationToken

	res, err := c.Context.client.CreateCard(req)
	if err != nil {
		return nil, err
	}

	return &Card{
		Context: c.Context,
		Model:   res,
	}, nil
}

func (c *cardManager) Revoke(card *Card, reason virgil.Enum) error {

	req, err := virgil.NewRevokeCardRequest(card.Model.ID, reason)
	if err != nil {
		return err
	}

	signer := &virgil.RequestSigner{}

	pk := c.Context.Config.Credentials.Key
	if pk == nil || pk.PrivateKey == nil {
		return errors.New("No app private key provided for request signing")
	}

	err = signer.AuthoritySign(req, c.Context.Config.Credentials.AppId, pk.PrivateKey)
	if err != nil {
		return err
	}

	return c.Context.client.RevokeCard(req)
}

func (c *cardManager) RevokeGlobal(card *Card, reason virgil.Enum, signerKey *Key, validationToken string) error {

	req, err := virgil.NewRevokeCardRequest(card.Model.ID, reason)
	if err != nil {
		return err
	}

	signer := &virgil.RequestSigner{}

	err = signer.AuthoritySign(req, card.Model.ID, signerKey.PrivateKey)
	if err != nil {
		return err
	}
	req.Meta.Validation = &virgil.ValidationInfo{}
	req.Meta.Validation.Token = validationToken

	return c.Context.client.RevokeCard(req)
}
