package securechat

type TalkManager struct {
	TalksByCardId    map[uint64]*SecureTalk
	TalksBySessionId map[uint64]*SecureTalk
}

func (s *TalkManager) GetBySessionId(sessionID []byte) *SecureTalk {
	sess, ok := s.TalksBySessionId[HashKey(sessionID)]
	if ok {
		return sess
	}
	return nil
}

func (s *TalkManager) AddBySessionID(id []byte, talk *SecureTalk) {
	s.TalksBySessionId[HashKey(id)] = talk
}

func (s *TalkManager) DeleteBySessionId(id []byte, talk *SecureTalk) {
	delete(s.TalksBySessionId, HashKey(id))
}

func (s *TalkManager) GetByCardId(cardID string) *SecureTalk {
	talk, ok := s.TalksByCardId[HashKey([]byte(cardID))]
	if ok {
		return talk
	}
	return nil
}

func (s *TalkManager) AddByCardId(talk *SecureTalk) {
	s.TalksByCardId[HashKey([]byte(talk.responderCardId))] = talk
}

func (s *TalkManager) DeleteByCardId(talk *SecureTalk) {
	delete(s.TalksByCardId, HashKey([]byte(talk.responderCardId)))
}
