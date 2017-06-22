package securechat

import (
	"time"

	"strconv"

	"os"

	"fmt"

	"encoding/json"

	"gopkg.in/virgil.v4"
	"gopkg.in/virgil.v4/clients/cardsroclient"
	"gopkg.in/virgil.v4/errors"
	"gopkg.in/virgil.v4/virgilcrypto"
)

const MaxOTCs = 100

type Api struct {
	pfsClient          *Client
	cardsClient        *cardsroclient.Client
	crypto             virgilcrypto.PFS
	talkManager        *TalkManager
	storage            virgil.KeyStorage
	identityCardID     string
	privateKey         virgilcrypto.PrivateKey
	privateKeyPassword string
	otcCount           int
}

var crypto = virgil.Crypto()

func New(config *Config) (*Api, error) {

	cli, err := config.PFSClient, error(nil)
	cardsCli := config.CardsClient

	if config.PFSClient == nil {
		cli, err = NewClient(config.AccessToken)
		if err != nil {
			return nil, err
		}
	}
	if config.CardsClient == nil {
		cardsCli, err = cardsroclient.New(config.AccessToken)
		if err != nil {
			return nil, err
		}
	}

	pfsCrypto, ok := crypto.(virgilcrypto.PFS)

	if !ok {
		return nil, errors.New("Crypto does not implement PFS")
	}

	pk, err := crypto.ImportPrivateKey(config.PrivateKey, config.PrivateKeyPassword)
	if err != nil {
		return nil, err
	}
	path := "."
	if config.KeyStoragePath != "" {
		path = config.KeyStoragePath
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		os.Mkdir(path, 700)
	}

	api := &Api{
		pfsClient:   cli,
		cardsClient: cardsCli,
		crypto:      pfsCrypto,
		talkManager: &TalkManager{
			TalksByCardId:    make(map[uint64]*SecureTalk),
			TalksBySessionId: make(map[uint64]*SecureTalk),
		},
		storage:            &virgil.FileStorage{RootDir: path},
		identityCardID:     config.IdentityCardID,
		privateKey:         pk,
		privateKeyPassword: config.PrivateKeyPassword,
	}

	if config.OTCCount < 1 {
		api.otcCount = MaxOTCs
	} else {
		api.otcCount = config.OTCCount
	}

	return api, nil

}

func (a *Api) BootstrapCardsSet() error {
	ltcKey, err := crypto.GenerateKeypair()
	if err != nil {
		return err
	}

	ltc, err := a.encryptEphemeralKey(ltcKey.PrivateKey())
	if err != nil {
		return err
	}

	ltcReq, err := virgil.NewCreateCardRequest(a.identityCardID, "ltc", ltcKey.PublicKey(), virgil.CardParams{})
	if err != nil {
		return err
	}

	err = ltcReq.AuthoritySign(a.identityCardID, a.privateKey)
	if err != nil {
		return err
	}

	otcRequests := make([]*virgil.SignableRequest, 0, a.otcCount)
	otcKeys := make(map[string]virgilcrypto.PrivateKey)
	for i := 0; i < a.otcCount; i++ {
		otcKey, err := crypto.GenerateKeypair()
		if err != nil {
			panic(err)
		}

		otcReq, err := virgil.NewCreateCardRequest(a.identityCardID, "otc", otcKey.PublicKey(), virgil.CardParams{})
		err = otcReq.AuthoritySign(a.identityCardID, a.privateKey)
		if err != nil {
			return err
		}

		otcRequests = append(otcRequests, otcReq)
		otcKeys[otcReq.ID()] = otcKey.PrivateKey()
	}

	t := time.Now()
	err = a.pfsClient.CreateRecipient(a.identityCardID, ltcReq, otcRequests)
	fmt.Println("req", time.Since(t))

	if err != nil {
		return err
	}

	a.storage.Store(&virgil.StorageItem{
		Name: ltcReq.ID(),
		Data: ltc,
		Meta: map[string]string{
			"type":    "ltc",
			"created": strconv.FormatInt(time.Now().Unix(), 10),
		},
	})

	for id, key := range otcKeys {

		otc, err := a.encryptEphemeralKey(key)
		if err != nil {
			return err
		}

		a.storage.Store(&virgil.StorageItem{
			Name: id,
			Data: otc,
			Meta: map[string]string{
				"type":    "otc",
				"created": strconv.FormatInt(time.Now().Unix(), 10),
			},
		})
	}
	return nil
}

func (a *Api) encryptEphemeralKey(key virgilcrypto.PrivateKey) ([]byte, error) {
	exportedKey, err := crypto.ExportPrivateKey(key, "")
	if err != nil {
		return nil, err
	}

	pub, err := crypto.ExtractPublicKey(a.privateKey)
	if err != nil {
		return nil, err
	}
	ct, err := crypto.Encrypt(exportedKey, pub)
	if err != nil {
		return nil, err
	}
	return ct, err
}

func (a *Api) decryptEphemeralKey(data []byte) (virgilcrypto.PrivateKey, error) {
	pt, err := crypto.Decrypt(data, a.privateKey)
	if err != nil {
		return nil, err
	}

	return crypto.ImportPrivateKey(pt, "")
}

func (a *Api) InitTalkWith(cardId string) (*SecureTalk, error) {

	if talk := a.talkManager.GetByCardId(cardId); talk != nil {
		return talk, nil
	}

	creds, err := a.pfsClient.GetUserCredentials(cardId)
	if err != nil {
		return nil, err
	}

	for _, c := range creds {
		EKa, err := crypto.GenerateKeypair()
		if err != nil {
			return nil, err
		}

		ad := append([]byte(a.identityCardID), []byte(c.IdentityCard.ID)...)
		ad = append(ad, []byte(c.LTC.ID)...)
		var otcPub virgilcrypto.PublicKey
		var otcID string
		ads, adw := ad, ad
		var session_s, session_w *virgilcrypto.PFSSession
		if c.OTC != nil {
			otcPub = c.OTC.PublicKey
			otcID = c.OTC.ID
			ads = append(ad, []byte(otcID)...)
			session_s, err = a.crypto.StartPFSSession(c.IdentityCard.PublicKey, c.LTC.PublicKey, otcPub, a.privateKey, EKa.PrivateKey(), ads)
			if err != nil {
				return nil, err
			}
		}

		session_w, err = a.crypto.StartPFSSession(c.IdentityCard.PublicKey, c.LTC.PublicKey, nil, a.privateKey, EKa.PrivateKey(), adw)
		if err != nil {
			return nil, err
		}

		EKaPub, err := crypto.ExportPublicKey(EKa.PublicKey())
		if err != nil {
			return nil, err
		}

		sign, err := crypto.Sign(EKaPub, a.privateKey)
		if err != nil {
			return nil, err
		}

		messageData := &Message{
			ID:        a.identityCardID,
			Eph:       EKaPub,
			Signature: sign,
			ICID:      c.IdentityCard.ID,
			LTCID:     c.LTC.ID,
			StrongSession: &StrongMessageSession{
				OTCID: c.OTC.ID,
			},
		}

		talk := &SecureTalk{
			weakSession:     session_w,
			strongSession:   session_s,
			responderCardId: cardId,
			initialMessage:  messageData,
			SessionManager: &SessionManager{
				Sessions: map[uint64]*virgilcrypto.PFSSession{
					HashKey(session_w.SessionID): session_w,
					HashKey(session_s.SessionID): session_s,
				},
			},
		}

		a.talkManager.AddBySessionID(session_s.SessionID, talk)
		a.talkManager.AddBySessionID(session_w.SessionID, talk)
		a.talkManager.AddByCardId(talk)
		return talk, nil

	}
	return nil, errors.New("No credentials found for card")
}

func (a *Api) InitTalkFromMessage(message virgil.Buffer) (*SecureTalk, error) {

	var msg *Message

	err := json.Unmarshal(message, &msg)
	if err != nil {
		return nil, err
	}

	if msg.SessionId != nil {
		if talk := a.talkManager.GetBySessionId(msg.SessionId); talk != nil {
			return talk, nil
		}
		return nil, errors.New("Session not found")
	}

	return a.receiveInitialMessage(msg)

}

func (a *Api) receiveInitialMessage(message *Message) (*SecureTalk, error) {

	err := a.validateInitialMessage(message)
	if err != nil {
		return nil, err
	}

	ICa, err := a.cardsClient.GetCard(message.ID)
	if err != nil {
		return nil, err
	}

	err = crypto.Verify(message.Eph, message.Signature, ICa.PublicKey)
	if err != nil {
		return nil, err
	}
	EKa, err := crypto.ImportPublicKey(message.Eph)
	if err != nil {
		return nil, err
	}

	ltcKeyData, err := a.storage.Load(message.LTCID)
	if err != nil {
		return nil, err
	}

	typ, ok := ltcKeyData.Meta["type"]

	if !ok {
		return nil, errors.New("could not determine private key type from storage")
	}

	if typ != "ltc" {
		return nil, errors.Errorf("Supplied card ID %s is not LTC", message.LTCID)
	}

	ltcKey, err := a.decryptEphemeralKey(ltcKeyData.Data)
	if err != nil {
		return nil, err
	}

	ad := append([]byte(message.ID), []byte(message.ICID)...)
	ad = append(ad, []byte(message.LTCID)...)

	var otcKey virgilcrypto.PrivateKey
	adw, ads := ad, ad
	var session_w, session_s *virgilcrypto.PFSSession

	if message.StrongSession != nil && message.StrongSession.OTCID != "" {
		otcKeyData, err := a.storage.Load(message.StrongSession.OTCID)
		if err != nil {
			return nil, err
		}

		typ, ok := otcKeyData.Meta["type"]

		if !ok {
			return nil, errors.New("could not determine private key type from storage")
		}

		if typ != "otc" {
			return nil, errors.Errorf("Supplied card ID %s is not OTC", message.StrongSession.OTCID)
		}

		otcKey, err = a.decryptEphemeralKey(otcKeyData.Data)
		if err != nil {
			return nil, err
		}
		a.storage.Delete(message.StrongSession.OTCID) //This is the core idea of PFS
		ads = append(ad, []byte(message.StrongSession.OTCID)...)

		session_s, err = a.crypto.ReceivePFCSession(ICa.PublicKey, EKa, a.privateKey, ltcKey, otcKey, ads)

		if err != nil {
			return nil, err
		}
	}

	session_w, err = a.crypto.ReceivePFCSession(ICa.PublicKey, EKa, a.privateKey, ltcKey, nil, adw)

	if err != nil {
		return nil, err
	}

	talk := &SecureTalk{
		responderCardId: message.ID,
		strongSession:   session_s,
		weakSession:     session_w,
		SessionManager: &SessionManager{
			Sessions: map[uint64]*virgilcrypto.PFSSession{
				HashKey(session_w.SessionID): session_w,
				HashKey(session_s.SessionID): session_s,
			},
		},
	}

	return talk, nil
}

func (a *Api) validateInitialMessage(msg *Message) error {
	if len(msg.ID) != 64 || len(msg.ICID) != 64 || len(msg.LTCID) != 64 ||
		msg.Eph == nil || msg.Signature == nil {
		return errors.New("initial message is incomplete")
	}

	if !isHex(msg.ID) || !isHex(msg.ICID) || !isHex(msg.LTCID) {
		return errors.New("invalid card ids")
	}

	if msg.ICID != a.identityCardID {
		return errors.New("Identity card ID mismatch")
	}

	if msg.StrongSession != nil && msg.StrongSession.OTCID != "" && (len(msg.StrongSession.OTCID) != 64 || !isHex(msg.StrongSession.OTCID)) {
		return errors.New("incorrect otc id")
	}

	if len(msg.Ciphertext) != 0 && len(msg.Salt) != 16 {
		return errors.New("invalid salt size")
	}

	if len(msg.Ciphertext) != 0 && len(msg.Ciphertext) < 16 {
		return errors.New("invalid ciphertext size")
	}
	return nil
}

func isHex(src string) bool {

	if len(src)%2 == 1 {
		return false
	}
	for i := 0; i < len(src); i++ {
		if !fromHexChar(src[i]) {
			return false
		}
	}
	return true
}

// fromHexChar converts a hex character into its value and a success flag.
func fromHexChar(c byte) bool {
	switch {
	case '0' <= c && c <= '9':
		return true
	case 'a' <= c && c <= 'f':
		return true
	case 'A' <= c && c <= 'F':
		return true
	}

	return false
}
