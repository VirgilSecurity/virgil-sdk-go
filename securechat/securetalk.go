package securechat

import (
	"encoding/json"

	"github.com/pkg/errors"
	"gopkg.in/virgil.v5"
	"gopkg.in/virgil.v5/virgilcrypto"
)

type SecureTalk struct {
	responderCardId string
	Session         *virgilcrypto.PFSSession
	used            bool
	initialMessage  *Message
}

func (s *SecureTalk) Encrypt(message virgil.Buffer) (virgil.Buffer, error) {

	salt, ct := s.Session.Encrypt(message)

	if s.initialMessage == nil {

		messages := make([]*Message, 0, 1)

		messages = append(messages, &Message{
			Salt:       salt,
			Ciphertext: ct,
			SessionId:  s.Session.SessionID,
		})

		return json.Marshal(messages)

	}

	s.initialMessage.Salt = salt
	s.initialMessage.Ciphertext = ct

	js, err := json.Marshal(s.initialMessage)
	s.initialMessage = nil
	return js, err
}

func (s *SecureTalk) Decrypt(message virgil.Buffer) (virgil.Buffer, error) {
	var msgs []*Message

	err := json.Unmarshal(message, &msgs)
	//array of messages for different sessions. Should be able to decrypt any of them
	if err == nil {

		for _, msg := range msgs {
			res, err := s.Session.Decrypt(msg.Salt, msg.Ciphertext)
			if err == nil {
				return res, nil
			}
		}
		return nil, errors.Wrap(err, "Could not find session for message")
	}

	var msg *Message
	err = json.Unmarshal(message, &msg)
	if err != nil {
		return nil, errors.Wrap(err, "Could not deserialize message")
	}

	res, err := s.Session.Decrypt(msg.Salt, msg.Ciphertext)
	if err == nil {
		return res, nil
	}

	return nil, nil //empty message
}
