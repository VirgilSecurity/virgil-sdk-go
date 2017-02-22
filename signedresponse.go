package virgil

import (
	"encoding/hex"
	"encoding/json"

	"gopkg.in/virgil.v4/errors"
)

type ResponseMeta struct {
	CreatedAt   string            `json:"created_at"`
	CardVersion string            `json:"card_version"`
	Signatures  map[string][]byte `json:"signs"`
	Relations   map[string][]byte `json:"relations"`
}

type CardResponse struct {
	ID       string       `json:"id"`
	Snapshot []byte       `json:"content_snapshot"`
	Meta     ResponseMeta `json:"meta"`
}

func (r *CardResponse) ToCard() (*Card, error) {

	fp := hex.EncodeToString(Crypto().CalculateFingerprint(r.Snapshot))
	if fp != r.ID {
		return nil, errors.New("Card ID and fingerprint do not match")
	}

	req := &CardModel{}
	err := json.Unmarshal(r.Snapshot, req)
	if err != nil {
		return nil, errors.Wrap(err, "Cannot convert response to Virgil Card")
	}

	kp, err := Crypto().ImportPublicKey(req.PublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "Cannot import public key from the Virgil Card")
	}
	card := &Card{
		ID:           r.ID,
		Snapshot:     r.Snapshot,
		Signatures:   r.Meta.Signatures,
		Identity:     req.Identity,
		IdentityType: req.IdentityType,
		PublicKey:    kp,
		Scope:        req.Scope,
		Data:         req.Data,
		DeviceInfo:   req.DeviceInfo,
		CreatedAt:    r.Meta.CreatedAt,
		CardVersion:  r.Meta.CardVersion,
		Relations:    r.Meta.Relations,
	}

	return card, nil
}
