package virgil

import (
	"encoding/json"

	"encoding/base64"

	"encoding/hex"

	"gopkg.in/virgil.v4/virgilcrypto"
)

// ffjson: skip
type CardParams struct {
	Scope      Enum
	Data       map[string]string
	DeviceInfo DeviceInfo
}
type CardModel struct {
	Identity     string            `json:"identity"`
	IdentityType string            `json:"identity_type"`
	PublicKey    []byte            `json:"public_key"` //DER encoded public key
	Scope        Enum              `json:"scope"`
	Data         map[string]string `json:"data,omitempty"`
	DeviceInfo   DeviceInfo        `json:"info"`
}

type SignableRequest struct {
	Snapshot []byte      `json:"content_snapshot"`
	Meta     RequestMeta `json:"meta"`
}

type RequestMeta struct {
	Signatures map[string][]byte `json:"signs"`
	Validation *ValidationInfo   `json:"validation,omitempty"`
}

type ValidationInfo struct {
	Token string `json:"token,omitempty"`
}

func NewCreateCardRequest(identity, identityType string, publicKey virgilcrypto.PublicKey, params CardParams) (*SignableRequest, error) {
	if params.Scope == "" {
		params.Scope = CardScope.Application
	}

	pub, err := publicKey.Encode()
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(CardModel{
		Identity:     identity,
		IdentityType: identityType,
		PublicKey:    pub,
		Scope:        params.Scope,
		Data:         params.Data,
		DeviceInfo:   params.DeviceInfo,
	})
	if err != nil {
		return nil, err
	}
	request := &SignableRequest{
		Snapshot: b,
		Meta: RequestMeta{
			Signatures: make(map[string][]byte, 0),
		},
	}
	return request, nil
}

func ImportCreateCardRequest(data []byte) (*SignableRequest, error) {

	raw := make([]byte, base64.StdEncoding.DecodedLen(len(data)))

	read, err := base64.StdEncoding.Decode(raw, data)
	if err != nil {
		return nil, err
	}
	raw = raw[:read]
	req := &SignableRequest{}
	err = json.Unmarshal(raw, &req)

	if err != nil {
		return nil, err
	}

	var ccreq CardModel

	err = json.Unmarshal(req.Snapshot, &ccreq)
	if err != nil {
		return nil, err
	}
	return req, nil
}

type RevokeCardRequest struct {
	ID               string `json:"card_id"`
	RevocationReason Enum   `json:"revocation_reason"`
}

func NewRevokeCardRequest(id string, revocationReason Enum) (*SignableRequest, error) {
	b, err := json.Marshal(&RevokeCardRequest{
		ID:               id,
		RevocationReason: revocationReason,
	})
	if err != nil {
		return nil, err
	}

	request := &SignableRequest{
		Snapshot: b,
		Meta: RequestMeta{
			Signatures: make(map[string][]byte, 0),
		},
	}

	return request, nil
}

func ImportRevokeCardRequest(data []byte) (*SignableRequest, error) {
	raw := make([]byte, base64.StdEncoding.DecodedLen(len(data)))

	read, err := base64.StdEncoding.Decode(raw, data)

	if err != nil {
		return nil, err
	}

	raw = raw[:read]
	req := &SignableRequest{}
	err = json.Unmarshal(raw, &req)

	if err != nil {
		return nil, err
	}

	revokeRequest := &RevokeCardRequest{}

	err = json.Unmarshal(req.Snapshot, revokeRequest)
	if err != nil {
		return nil, err
	}

	return req, nil
}

func (r *SignableRequest) AppendSignature(cardId string, signature []byte) {
	r.Meta.Signatures[cardId] = signature
}

func (r *SignableRequest) Export() ([]byte, error) {
	res, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}

	b := make([]byte, base64.StdEncoding.EncodedLen(len(res)))
	base64.StdEncoding.Encode(b, res)
	return b, nil
}

func NewAddRelationRequest(relationCard *Card) (*SignableRequest, error) {
	return &SignableRequest{
		Snapshot: relationCard.Snapshot,
		Meta: RequestMeta{
			Signatures: make(map[string][]byte, 0),
		},
	}, nil
}

func ImportAddRelationRequest(data []byte) (*SignableRequest, error) {

	raw := make([]byte, base64.StdEncoding.DecodedLen(len(data)))

	read, err := base64.StdEncoding.Decode(raw, data)
	if err != nil {
		return nil, err
	}
	raw = raw[:read]
	req := &SignableRequest{}
	err = json.Unmarshal(raw, &req)

	if err != nil {
		return nil, err
	}

	return req, nil
}

func NewDeleteRelationRequest(relationCardId string) (*SignableRequest, error) {

	b, err := json.Marshal(&RevokeCardRequest{
		ID:               relationCardId,
		RevocationReason: "unspecified",
	})
	if err != nil {
		return nil, err
	}

	return &SignableRequest{
		Snapshot: b,
		Meta: RequestMeta{
			Signatures: make(map[string][]byte, 0),
		},
	}, nil
}

func ImportDeleteRelationRequest(data []byte) (*SignableRequest, error) {

	raw := make([]byte, base64.StdEncoding.DecodedLen(len(data)))

	read, err := base64.StdEncoding.Decode(raw, data)
	if err != nil {
		return nil, err
	}
	raw = raw[:read]
	req := &SignableRequest{}
	err = json.Unmarshal(raw, &req)

	if err != nil {
		return nil, err
	}

	return req, nil
}

func (s *SignableRequest) SelfSign(privateKey virgilcrypto.PrivateKey) error {

	fp := Crypto().CalculateFingerprint(s.Snapshot)

	sign, err := Crypto().Sign(fp, privateKey)

	if err != nil {
		return err
	}
	s.AppendSignature(hex.EncodeToString(fp), sign)
	return nil
}

func (s *SignableRequest) AuthoritySign(cardId string, privateKey virgilcrypto.PrivateKey) error {

	fp := Crypto().CalculateFingerprint(s.Snapshot)

	sign, err := Crypto().Sign(fp, privateKey)
	if err != nil {
		return err
	}

	s.AppendSignature(cardId, sign)
	return nil
}
