package pfs

import (
	"time"

	"strconv"

	"os"

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
		pfsClient:          cli,
		cardsClient:        cardsCli,
		crypto:             pfsCrypto,
		sessionManager:     &SessionManager{Sessions: make(map[uint64]*virgilcrypto.PFSSession)},
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

func (a *Api) Bootstrap() error {
	ltcKey, err := crypto.GenerateKeypair()
	if err != nil {
		return err
	}

	ltc, err := a.EncryptEphemeralKey(ltcKey.PrivateKey())
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

		otc, err := a.EncryptEphemeralKey(key)
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

func (a *Api) EncryptEphemeralKey(key virgilcrypto.PrivateKey) ([]byte, error) {
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

func (a *Api) DecryptEphemeralKey(data []byte) (virgilcrypto.PrivateKey, error) {
	pt, err := crypto.Decrypt(data, a.privateKey)
	if err != nil {
		return nil, err
	}

	return crypto.ImportPrivateKey(pt, "")
}

func (a *Api) InitTalkWith(identity string, message virgil.Buffer) ([]*Message, error) {

	creds, err := a.pfsClient.GetUserCredentials(identity)
	if err != nil {
		return nil, err
	}
	messages := make([]*Message, 0, len(creds))
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

		EKaPub, err := crypto.ExportPublicKey(EKa.PublicKey())
		if err != nil {
			return nil, err
		}

		sign, err := crypto.Sign(EKaPub, a.privateKey)
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

	err := a.ValidateInitialMessage(message)
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

	ltcKey, err := a.DecryptEphemeralKey(ltcKeyData.Data)
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

		otcKey, err = a.DecryptEphemeralKey(otcKeyData.Data)
		if err != nil {
			return nil, err
		}
		a.storage.Delete(message.OTCID) //This is the core idea of PFS
		ad = append(ad, []byte(message.OTCID)...)
	}

	sess, err := a.crypto.ReceivePFCSession(ICa.PublicKey, EKa, a.privateKey, ltcKey, otcKey, ad)

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

func (a *Api) ValidateInitialMessage(msg *Message) error {
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

func (a *Api) ReceiveSessionMessage(message *Message) (virgil.Buffer, error) {

	if len(message.SessionId) != 32 {
		return nil, errors.New("Invalid session id")
	}

	if len(message.Salt) != 16 {
		return nil, errors.New("Invalid salt")
	}

	if len(message.Ciphertext) < 16 {
		return nil, errors.New("Invalid ciphertext")
	}

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
