package securechat

import "gopkg.in/virgil.v5/virgilcrypto"

type SessionManager struct {
	Sessions map[uint64]*virgilcrypto.PFSSession
}

func (s *SessionManager) GetBySessionId(sessionID []byte) *virgilcrypto.PFSSession {
	sess, ok := s.Sessions[HashKey(sessionID)]
	if ok {
		return sess
	}
	return nil
}

func (s *SessionManager) AddBySessionID(sess *virgilcrypto.PFSSession) {
	s.Sessions[HashKey(sess.SessionID)] = sess
}

func (s *SessionManager) DeleteBySessionId(sess *virgilcrypto.PFSSession) {
	delete(s.Sessions, HashKey(sess.SessionID))
}

func (s *SessionManager) DeleteAllExceptID(sessionId []byte) {
	var keyToRemove uint64
	goodKey := HashKey(sessionId)
	for k := range s.Sessions {
		if k != goodKey {
			keyToRemove = k
			break
		}
	}

	delete(s.Sessions, keyToRemove)
}
