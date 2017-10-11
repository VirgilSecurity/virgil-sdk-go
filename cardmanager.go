package virgilcards

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/pkg/errors"

	"gopkg.in/virgil.v6/common"
	"gopkg.in/virgil.v6/crypto-api"
)

type Validator interface {
	Validate(card Card) error
}

type SignerType string

const (
	SignerTypeSelf        SignerType = "self"
	SignerTypeApplication SignerType = "app"
	SignerTypeVirgil      SignerType = "virgil"
	SignerTypeCustom      SignerType = "extra"
)

type CardSignature struct {
	SignerCardId string
	Signature    []byte
	ExtraFields  map[string]string
	SignerType   SignerType
	Snapshot     []byte
}

type Card struct {
	ID        string
	Identity  string
	PublicKey cryptoapi.PublicKey
	Version   string
	CreatedAt time.Time
	Signature []CardSignature
	Snapshot  []byte
}

type RawCardSignature struct {
	SignerCardId string `json:"signer_card_id"`
	Signature    []byte `json:"signature"`
	ExtraFields  []byte `json:"snapshot"`
	SignerType   string `json:"signer_type"`
}

type RawCardMeta struct {
	Signatures map[string][]byte `json:"signs"`
	CreatedAt  string            `json:"created_at"`
	Version    string            `json:"card_version"`
}
type RawCardSnapshot struct {
	Identity       string `json:"identity"`
	PublicKeyBytes []byte `json:"public_key"`
	Version        string `json:"version"`
	CreatedAt      int64  `json:"created_at"`
}
type RawCard struct {
	Snapshot   []byte             `json:"content_snapshot"`
	Signatures []RawCardSignature `json:"signatures"`
	Meta       RawCardMeta        `json:"meta"`
}

type CardsManager struct {
	Crypto     cryptoapi.Crypto
	Validator  Validator
	ApiUrl     string
	HttpClient *http.Client
}

func (cm *CardsManager) GetCard(id string) (Card, error) {
	var rawCard RawCard
	err := cm.send(http.MethodGet, "/v5/card/"+id, nil, &rawCard)
	if err != nil {
		return Card{}, err
	}
	card, err := cm.raw2Card(rawCard)
	if err != nil {
		return Card{}, err
	}

	err = cm.validate([]Card{card})
	return card, err
}

func (cm *CardsManager) SearchCards(identity string) ([]Card, error) {
	var rawCards []RawCard
	err := cm.send(http.MethodPost, "/v5/card/actions/search", map[string]string{"identity": identity}, &rawCards)
	if err != nil {
		return []Card{}, err
	}

	cards := make([]Card, len(rawCards))
	for i, rc := range rawCards {
		cards[i], err = cm.raw2Card(rc)
		if err != nil {
			return []Card{}, err
		}
	}

	err = cm.validate(cards)
	return cards, err
}

func (cm *CardsManager) PublishCard(scr CSR) (Card, error) {
	var rawCard RawCard
	err := cm.send(http.MethodPost, "/v5/card", RawCard{Signatures: scr.Signatures, Snapshot: scr.Snapshot}, &rawCard)
	if err != nil {
		return Card{}, err
	}
	card, err := cm.raw2Card(rawCard)
	if err != nil {
		return Card{}, err
	}

	err = cm.validate([]Card{card})
	return card, err
}

func (cm *CardsManager) GenerateCSR(param CSRParams) (CSR, error) {
	if param.PublicKey == nil {
		return CSR{}, CSRPublicKeyEmptyErr
	}
	if param.Identity == "" {
		return CSR{}, CSRIdentityEmptyErr
	}
	exportedPubKey, err := cm.getCrypto().ExportPublicKey(param.PublicKey)
	if err != nil {
		return CSR{}, err
	}
	t := time.Now().UTC().Unix()
	cardInfo := RawCardSnapshot{
		Identity:       param.Identity,
		PublicKeyBytes: exportedPubKey,
		Version:        "5.0",
		CreatedAt:      t,
	}
	snapshot, err := json.Marshal(cardInfo)
	if err != nil {
		return CSR{}, errors.Wrap(err, "CardsManager: marshaling card's info")
	}
	csr := CSR{
		ID:             hex.EncodeToString(cm.getCrypto().CalculateFingerprint(snapshot)),
		CreatedAt:      cardInfo.CreatedAt,
		Identity:       cardInfo.Identity,
		PublicKeyBytes: cardInfo.PublicKeyBytes,
		Version:        cardInfo.Version,
		Snapshot:       snapshot,
		Signatures:     []RawCardSignature{},
	}
	if param.PrivateKey != nil {
		err := csr.Sign(cm.getCrypto(), CSRSignParams{
			ExtraFields:      param.ExtraFields,
			SignerCardId:     "",
			SignerType:       SignerTypeSelf,
			SignerPrivateKey: param.PrivateKey,
		})
		if err != nil {
			return csr, err
		}
	}
	return csr, nil
}

func (cm *CardsManager) SignCSR(csr *CSR, params CSRSignParams) error {
	return csr.Sign(cm.getCrypto(), params)
}

func (cm *CardsManager) ImportCSR(source []byte) (CSR, error) {
	var csr CSR
	var raw RawCard
	err := json.Unmarshal(source, &raw)
	if err != nil {
		return csr, errors.Wrap(err, "CardsMangerImportCSR.: unmarshal source")
	}
	var info RawCardSnapshot
	err = json.Unmarshal(raw.Snapshot, &info)
	if err != nil {
		return csr, errors.Wrap(err, "CardsMangerImportCSR.: unmarshal csr snapshot info")
	}
	csr = CSR{
		Identity:       info.Identity,
		PublicKeyBytes: info.PublicKeyBytes,
		Snapshot:       raw.Snapshot,
		Version:        info.Version,
		CreatedAt:      info.CreatedAt,
		Signatures:     raw.Signatures,
	}

	sn := raw.Snapshot
	index := sliceIndex(len(csr.Signatures), func(i int) bool {
		return csr.Signatures[i].SignerType == string(SignerTypeSelf)
	})
	if index != -1 && len(csr.Signatures[index].ExtraFields) != 0 {
		sn = append(sn, csr.Signatures[index].ExtraFields...)
	}
	csr.ID = hex.EncodeToString(cm.getCrypto().CalculateFingerprint(sn))

	return csr, nil
}

func (cm *CardsManager) validate(cards []Card) error {
	if cm.Validator == nil {
		return nil
	}
	for _, card := range cards {
		err := cm.Validator.Validate(card)
		if err != nil {
			return err
		}
	}
	return nil
}

func (cm *CardsManager) raw2Card(raw RawCard) (card Card, err error) {
	var cardInfo RawCardSnapshot

	err = json.Unmarshal(raw.Snapshot, &cardInfo)
	if err != nil {
		return card, errors.Wrap(err, "CardsManager: cannot unmarshal card snapshot")
	}
	pubKey, err := cm.getCrypto().ImportPublicKey(cardInfo.PublicKeyBytes)
	if err != nil {
		return card, err
	}
	card.PublicKey = pubKey
	card.Identity = cardInfo.Identity
	card.Snapshot = raw.Snapshot

	if cardInfo.Version == "5.0" {
		card.CreatedAt = time.Unix(cardInfo.CreatedAt, 0)
		card.Version = cardInfo.Version
		card.Signature = make([]CardSignature, len(raw.Signatures))
		for i, rs := range raw.Signatures {
			cs := CardSignature{
				SignerCardId: rs.SignerCardId,
				Signature:    rs.Signature,
				SignerType:   SignerType(rs.SignerType),
				Snapshot:     []byte{},
			}
			if rs.ExtraFields != nil {
				var exf map[string]string
				err = json.Unmarshal(rs.ExtraFields, &exf)
				if err != nil {
					return card, errors.Wrap(err, "CardsManager: unmarshal extrafileds of signature")
				}
				cs.ExtraFields = exf
				cs.Snapshot = rs.ExtraFields
			}

			card.Signature[i] = cs
			if card.Signature[i].SignerType == SignerTypeSelf {
				fpData := append(raw.Snapshot, rs.ExtraFields...)
				fp := cm.getCrypto().CalculateFingerprint(fpData)
				card.ID = hex.EncodeToString(fp)
			}
		}

	} else { // try convert from 4.0 to 5.0
		card.Version = raw.Meta.Version
		t, err := time.Parse("2006-01-02T15:04:05-0700", raw.Meta.CreatedAt)
		if err != nil {
			return card, errors.Wrap(err, "CardsManager: error parse of time of create card of v4 format")
		}
		card.CreatedAt = t

		fp := cm.getCrypto().CalculateFingerprint(raw.Snapshot)
		card.ID = hex.EncodeToString(fp)

		card.Signature = make([]CardSignature, len(raw.Meta.Signatures))
		var i = 0
		for signerID, sign := range raw.Meta.Signatures {
			var signType = SignerTypeCustom
			if signerID == card.ID {
				signType = SignerTypeSelf
			}
			card.Signature[i] = CardSignature{
				Signature:    sign,
				SignerCardId: signerID,
				SignerType:   signType,
				Snapshot:     []byte{},
			}
		}
	}

	return
}

func (cm *CardsManager) send(method string, url string, payload interface{}, respObj interface{}) error {
	client := cm.getVirgilClient()
	err := client.Send(method, url, payload, respObj)
	if err != nil {
		if apiErr, ok := err.(common.VirgilAPIError); ok {
			return CardsAPIError(apiErr)
		}
		return err
	}
	return nil
}

func (cm *CardsManager) getCrypto() cryptoapi.Crypto {
	if cm.Crypto != nil {
		return cm.Crypto
	}
	return DefaultCrypto
}

func (cm *CardsManager) getUrl() string {
	if cm.ApiUrl != "" {
		return cm.ApiUrl
	}
	return "https://api.virgilsecurity.com"
}

func (cm *CardsManager) getHttpClient() *http.Client {
	if cm.HttpClient != nil {
		return cm.HttpClient
	}
	return http.DefaultClient
}

func (cm *CardsManager) getVirgilClient() common.VirgilHttpClient {
	return common.VirgilHttpClient{
		Address: cm.getUrl(),
		Client:  cm.getHttpClient(),
	}
}
