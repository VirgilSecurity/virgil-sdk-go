package securechat

type SessionManager struct {
	SessionsByCardId map[uint64]*Session
	SessionsById     map[uint64]*Session
}

func (s *SessionManager) GetBySessionId(sessionID []byte) *Session {
	sess, ok := s.SessionsById[HashKey(sessionID)]
	if ok {
		return sess
	}
	return nil
}

func (s *SessionManager) AddBySessionID(id []byte, session *Session) {
	s.SessionsById[HashKey(id)] = session
}

func (s *SessionManager) DeleteBySessionId(id []byte, session *Session) {
	delete(s.SessionsById, HashKey(id))
}

func (s *SessionManager) GetByCardId(cardID string) *Session {
	talk, ok := s.SessionsByCardId[HashKey([]byte(cardID))]
	if ok {
		return talk
	}
	return nil
}

func (s *SessionManager) AddByCardId(session *Session) {
	s.SessionsByCardId[HashKey([]byte(session.responderCardId))] = session
}

func (s *SessionManager) DeleteByCardId(session *Session) {
	delete(s.SessionsByCardId, HashKey([]byte(session.responderCardId)))
}
