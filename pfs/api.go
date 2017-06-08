package pfs

import (
	"time"

	"strconv"

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
	sessionManager     *SessionManager
	storage            virgil.KeyStorage
	identityCardID     string
	privateKey         virgilcrypto.PrivateKey
	privateKeyPassword string
	otcCount           int
}

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

	pfsCrypto, ok := virgil.Crypto().(virgilcrypto.PFS)

	if !ok {
		return nil, errors.New("Crypto does not implement PFS")
	}

	pk, err := virgil.Crypto().ImportPrivateKey(config.PrivateKey, config.PrivateKeyPassword)
	if err != nil {
		return nil, err
	}

	api := &Api{
		pfsClient:          cli,
		cardsClient:        cardsCli,
		crypto:             pfsCrypto,
		sessionManager:     &SessionManager{Sessions: make(map[uint64]*virgilcrypto.PFSSession)},
		storage:            &virgil.FileStorage{RootDir: "d:\\Keys"},
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

func (a *Api) Bootstrap() error {
	ltcKey, err := virgil.Crypto().GenerateKeypair()
	if err != nil {
		return err
	}

	exportedLTCKey, err := virgil.Crypto().ExportPrivateKey(ltcKey.PrivateKey(), "")
	if err != nil {
		return err
	}

	ltcReq, err := virgil.NewCreateCardRequest(a.identityCardID, "ltc", ltcKey.PublicKey(), virgil.CardParams{})
	if err != nil {
		return err
	}
	err = ltcReq.SelfSign(ltcKey.PrivateKey())
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
		otcKey, err := virgil.Crypto().GenerateKeypair()
		if err != nil {
			panic(err)
		}

		otcReq, err := virgil.NewCreateCardRequest(a.identityCardID, "otc", otcKey.PublicKey(), virgil.CardParams{})
		otcReq.SelfSign(otcKey.PrivateKey())
		otcReq.AuthoritySign(a.identityCardID, a.privateKey)

		otcRequests = append(otcRequests, otcReq)
		otcKeys[otcReq.ID()] = otcKey.PrivateKey()
	}

	recipient, err := a.pfsClient.CreateRecipient(a.identityCardID, ltcReq, otcRequests)

	if err != nil {
		return err
	}

	a.storage.Store(&virgil.StorageItem{
		Name: recipient.LTC.ID,
		Data: exportedLTCKey,
		Meta: map[string]string{
			"type":    "ltc",
			"created": strconv.FormatInt(time.Now().Unix(), 10),
		},
	})

	for id, key := range otcKeys {

		exportedOTCKey, err := virgil.Crypto().ExportPrivateKey(key, "")
		if err != nil {
			return err
		}

		a.storage.Store(&virgil.StorageItem{
			Name: id,
			Data: exportedOTCKey,
			Meta: map[string]string{
				"type":    "otc",
				"created": strconv.FormatInt(time.Now().Unix(), 10),
			},
		})
	}
	return nil
}

func (a *Api) InitTalkWith(identity string, message virgil.Buffer) ([]*Message, error) {

	creds, err := a.pfsClient.GetUserCredentials(identity)
	if err != nil {
		return nil, err
	}
	messages := make([]*Message, 0, len(creds))
	for _, c := range creds {
		EKa, err := virgil.Crypto().GenerateKeypair()
		if err != nil {
			return nil, err
		}
		var otcPub virgilcrypto.PublicKey
		var otcID string
		if c.OTC != nil {
			otcPub = c.OTC.PublicKey
			otcID = c.OTC.ID
		}
		session, err := a.crypto.StartPFSSession(c.IdentityCard.PublicKey, c.LTC.PublicKey, otcPub, a.privateKey, EKa.PrivateKey(), a.identityCardID, c.IdentityCard.ID)

		EKaPub, err := virgil.Crypto().ExportPublicKey(EKa.PublicKey())
		if err != nil {
			return nil, err
		}

		sign, err := virgil.Crypto().Sign(EKaPub, a.privateKey)
		if err != nil {
			return nil, err
		}

		salt, ciphertext := session.Encrypt(message)

		messageData := &Message{
			ID:         a.identityCardID,
			Eph:        EKaPub,
			Signature:  sign,
			ICID:       c.IdentityCard.ID,
			LTCID:      c.LTC.ID,
			OTCID:      otcID,
			Salt:       salt,
			Ciphertext: ciphertext,
		}

		a.sessionManager.AddSession(session)
		messages = append(messages, messageData)

	}
	return messages, nil
}

func (a *Api) ReceiveMessage(message *Message) (virgil.Buffer, error) {
	if message == nil {
		return nil, errors.New("Message is nil")
	}

	if message.SessionId != nil {
		return a.ReceiveSessionMessage(message)
	}

	if message.ID != "" {
		return a.ReceiveInitialMessage(message)
	}
	return nil, errors.New("invalid message")
}

func (a *Api) ReceiveInitialMessage(message *Message) (virgil.Buffer, error) {
	if message.ID == "" || message.ICID == "" || message.LTCID == "" ||
		message.Eph == nil || message.Signature == nil {
		return nil, errors.New("initial message is incomplete")
	}

	if message.ICID != a.identityCardID {
		return nil, errors.New("Identity card ID mismatch")
	}

	ICa, err := a.cardsClient.GetCard(message.ID)
	if err != nil {
		return nil, err
	}

	err = virgil.Crypto().Verify(message.Eph, message.Signature, ICa.PublicKey)
	if err != nil {
		return nil, err
	}
	EKa, err := virgil.Crypto().ImportPublicKey(message.Eph)
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

	ltcKey, err := virgil.Crypto().ImportPrivateKey(ltcKeyData.Data, "")
	if err != nil {
		return nil, err
	}

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

		otcKey, err = virgil.Crypto().ImportPrivateKey(otcKeyData.Data, "")
		if err != nil {
			return nil, err
		}
	}

	sess, err := a.crypto.ReceivePFCSession(ICa.PublicKey, EKa, a.privateKey, ltcKey, otcKey, message.ID, a.identityCardID)

	if err != nil {
		return nil, err
	}

	var plaintext virgil.Buffer
	if message.Salt != nil && message.Ciphertext != nil {
		plaintext, err = sess.Decrypt(message.Salt, message.Ciphertext)
		if err != nil {
			return nil, err
		}
	}

	a.sessionManager.AddSession(sess)

	return plaintext, nil
}

func (a *Api) ReceiveSessionMessage(message *Message) (virgil.Buffer, error) {
	session := a.sessionManager.GetSession(message.SessionId)
	if session == nil {
		return nil, errors.New("Session not found")
	}

	plaintext, err := session.Decrypt(message.Salt, message.Ciphertext)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
