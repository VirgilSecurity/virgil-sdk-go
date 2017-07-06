package securechat

import (
	"time"

	"strconv"

	"os"

	"encoding/json"

	"gopkg.in/virgil.v5"
	"gopkg.in/virgil.v5/clients/cardsroclient"
	"gopkg.in/virgil.v5/errors"
	"gopkg.in/virgil.v5/virgilcrypto"
)

const MaxOTCs = 100

type Api struct {
	pfsClient          *Client
	cardsClient        *cardsroclient.Client
	crypto             virgilcrypto.PFS
	sessionManager     *SessionManager
	storage            virgil.KeyStorage
	identityCardID     string
	privateKey         virgilcrypto.PrivateKey
	privateKeyPassword string
	otcCount           int
}

var crypto = virgil.Crypto()

func New(preferences *Preferences) (*Api, error) {

	cli, err := preferences.PFSClient, error(nil)
	cardsCli := preferences.CardsClient

	if preferences.PFSClient == nil {
		cli, err = NewClient(preferences.AccessToken)
		if err != nil {
			return nil, err
		}
	}
	if preferences.CardsClient == nil {
		cardsCli, err = cardsroclient.New(preferences.AccessToken)
		if err != nil {
			return nil, err
		}
	}

	pfsCrypto, ok := crypto.(virgilcrypto.PFS)

	if !ok {
		return nil, errors.New("Crypto does not implement PFS")
	}

	pk, err := crypto.ImportPrivateKey(preferences.PrivateKey, preferences.PrivateKeyPassword)
	if err != nil {
		return nil, err
	}
	path := "."
	if preferences.KeyStoragePath != "" {
		path = preferences.KeyStoragePath
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		os.Mkdir(path, 700)
	}

	api := &Api{
		pfsClient:   cli,
		cardsClient: cardsCli,
		crypto:      pfsCrypto,
		sessionManager: &SessionManager{
			SessionsByCardId: make(map[uint64]*Session),
			SessionsById:     make(map[uint64]*Session),
		},
		storage:            &virgil.FileStorage{RootDir: path},
		identityCardID:     preferences.IdentityCardID,
		privateKey:         pk,
		privateKeyPassword: preferences.PrivateKeyPassword,
	}

	if preferences.OTCCount < 1 {
		api.otcCount = MaxOTCs
	} else {
		api.otcCount = preferences.OTCCount
	}

	return api, nil

}

func (a *Api) GetActiveSession(cardId string) *Session {
	sess := a.sessionManager.GetByCardId(cardId)
	if sess == nil || sess.IsExpired() {
		return nil
	}
	return sess
}

func (a *Api) LoadUpSession(card *virgil.Card, message virgil.Buffer) (sess *Session, err error) {
	sess = a.sessionManager.GetByCardId(card.ID)
	if sess == nil {
		sess, err = a.EstablishSessionByMessage(card, message)
		if err != nil {
			return nil, err
		}
		a.sessionManager.AddByCardId(sess)
	}
	return sess, nil
}

func (a *Api) SendMessage(receiver string, message virgil.Buffer) (virgil.Buffer, error) {
	sess := a.sessionManager.GetByCardId(receiver)
	var err error
	if sess == nil || sess.IsExpired() {
		sess, err = a.StartNewSessionWith(receiver)
		if err != nil {
			return nil, err
		}
		a.sessionManager.AddByCardId(sess)
	}

	return sess.Encrypt(message)
}

/*func (a *Api) ReceiveMessage(sender string, message virgil.Buffer) (virgil.Buffer, error) {
	sess := a.sessionManager.GetByCardId(sender)
	var err error
	if sess == nil {

		sess, err = a.EstablishSessionByMessage(message)
		if err != nil {
			return nil, err
		}
		a.sessionManager.AddByCardId(sess)
	}

	return sess.Decrypt(message)
}*/

func (a *Api) Initialize() error {
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

	err = a.pfsClient.CreateRecipient(a.identityCardID, ltcReq, otcRequests)

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

func (a *Api) StartNewSessionWith(cardId string) (*Session, error) {

	if talk := a.sessionManager.GetByCardId(cardId); talk != nil {
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
		if c.OTC != nil {
			otcPub = c.OTC.PublicKey
			otcID = c.OTC.ID
			ad = append(ad, []byte(otcID)...)

		}

		session, err := a.crypto.StartPFSSession(c.IdentityCard.PublicKey, c.LTC.PublicKey, otcPub, a.privateKey, EKa.PrivateKey(), ad)
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
			OTCID:     c.OTC.ID,
		}

		talk := &Session{
			Session:         session,
			responderCardId: cardId,
			initialMessage:  messageData,
		}

		a.sessionManager.AddBySessionID(session.SessionID, talk)
		a.sessionManager.AddByCardId(talk)
		return talk, nil

	}
	return nil, errors.New("No credentials found for card")
}

func (a *Api) EstablishSessionByMessage(card *virgil.Card, message virgil.Buffer) (*Session, error) {

	var msg *Message

	err := json.Unmarshal(message, &msg)
	if err != nil {
		return nil, err
	}

	if msg.SessionId != nil {
		if talk := a.sessionManager.GetBySessionId(msg.SessionId); talk != nil {
			return talk, nil
		}
		return nil, errors.New("Session not found")
	}

	return a.receiveInitialMessage(card, msg)

}

func (a *Api) receiveInitialMessage(identityCard *virgil.Card, message *Message) (*Session, error) {

	err := a.validateInitialMessage(message)
	if err != nil {
		return nil, err
	}

	if identityCard == nil {
		return nil, errors.New("No identity card provided")
	}

	if identityCard.ID != message.ID {
		return nil, errors.New("The provided card does not correspond to the identity card ID in message")
	}

	err = crypto.Verify(message.Eph, message.Signature, identityCard.PublicKey)
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

	if message.OTCID != "" {
		otcKeyData, err := a.storage.Load(message.OTCID)
		if err != nil {
			return nil, err
		}

		typ, ok := otcKeyData.Meta["type"]

		if !ok {
			return nil, errors.New("could not determine private key type from storage")
		}

		if typ != "otc" {
			return nil, errors.Errorf("Supplied card ID %s is not OTC", message.OTCID)
		}

		otcKey, err = a.decryptEphemeralKey(otcKeyData.Data)
		if err != nil {
			return nil, err
		}
		a.storage.Delete(message.OTCID) //This is the core idea of PFS
		ad = append(ad, []byte(message.OTCID)...)

	}

	session, err := a.crypto.ReceivePFCSession(identityCard.PublicKey, EKa, a.privateKey, ltcKey, otcKey, ad)

	if err != nil {
		return nil, err
	}

	talk := &Session{
		responderCardId: message.ID,
		Session:         session,
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

	if msg.OTCID != "" && (len(msg.OTCID) != 64 || !isHex(msg.OTCID)) {
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
