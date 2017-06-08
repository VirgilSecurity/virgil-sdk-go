package pfs

import "gopkg.in/virgil.v4/virgilcrypto"

type SessionManager struct {
	Sessions map[uint64]*virgilcrypto.PFSSession
}

func (s *SessionManager) GetSession(sessionID []byte) *virgilcrypto.PFSSession {
	sess, ok := s.Sessions[HashKey(sessionID)]
	if ok {
		return sess
	}
	return nil
}

func (s *SessionManager) AddSession(sess *virgilcrypto.PFSSession) {
	s.Sessions[HashKey(sess.SessionID)] = sess
}

func (s *SessionManager) DeleteSession(sess *virgilcrypto.PFSSession) {
	delete(s.Sessions, HashKey(sess.SessionID))
}
