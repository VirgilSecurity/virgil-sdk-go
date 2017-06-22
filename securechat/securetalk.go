package securechat

import (
	"encoding/json"

	"github.com/pkg/errors"
	"gopkg.in/virgil.v4"
	"gopkg.in/virgil.v4/virgilcrypto"
)

type SecureTalk struct {
	responderCardId string
	weakSession     *virgilcrypto.PFSSession
	strongSession   *virgilcrypto.PFSSession
	SessionManager  *SessionManager

	used           bool
	initialMessage *Message
}

func (s *SecureTalk) Encrypt(message virgil.Buffer) (virgil.Buffer, error) {

	if s.initialMessage == nil {

		messages := make([]*Message, 0)
		if s.strongSession != nil {
			messages = append(messages, encryptMessageWithSession(message, s.strongSession))
		}

		if s.weakSession != nil {
			messages = append(messages, encryptMessageWithSession(message, s.weakSession))
		}

		return json.Marshal(messages)

	}

	if s.weakSession != nil {
		msg := encryptMessageWithSession(message, s.weakSession)
		s.initialMessage.WeakSession = &WeakMessageSession{
			Salt:       msg.Salt,
			Ciphertext: msg.Ciphertext,
		}
	}

	if s.strongSession != nil {

		if s.initialMessage.StrongSession == nil {
			return nil, errors.New("No OTCID is set for strong session")
		}

		msg := encryptMessageWithSession(message, s.strongSession)
		s.initialMessage.StrongSession.Salt = msg.Salt
		s.initialMessage.StrongSession.Ciphertext = msg.Ciphertext
	}

	js, err := json.Marshal(s.initialMessage)
	s.initialMessage = nil
	return js, err
}

func encryptMessageWithSession(msg virgil.Buffer, session *virgilcrypto.PFSSession) *Message {
	salt, ct := session.Encrypt(msg)
	return &Message{
		SessionId:  session.SessionID,
		Salt:       salt,
		Ciphertext: ct,
	}
}

func (s *SecureTalk) Decrypt(message virgil.Buffer) (virgil.Buffer, error) {
	var msgs []*Message

	err := json.Unmarshal(message, &msgs)
	//array of messages for different sessions. Should be able to decrypt any of them
	if err == nil {

		//responder chose one of the sessions, drop another
		/*if len(msgs) == 1 && len(s.SessionManager.Sessions) == 2 {
			s.SessionManager.DeleteAllExceptID(msgs[0].SessionId)
		}*/

		for _, msg := range msgs {
			sess := s.SessionManager.GetBySessionId(msg.SessionId)
			if sess != nil {
				res, err := sess.Decrypt(msg.Salt, msg.Ciphertext)
				if err == nil {
					return res, nil
				}
			}
		}
		return nil, errors.Wrap(err, "Could not decrypt message")
	}

	var msg *Message
	err = json.Unmarshal(message, &msg)
	if err != nil {
		return nil, errors.Wrap(err, "Could not deserialize message")
	}

	if msg.StrongSession != nil {
		res, err := s.strongSession.Decrypt(msg.StrongSession.Salt, msg.StrongSession.Ciphertext)
		if err == nil {
			return res, nil
		}
	}

	if msg.WeakSession != nil {
		return s.weakSession.Decrypt(msg.StrongSession.Salt, msg.StrongSession.Ciphertext)
	}

	return nil, nil //empty message

}
