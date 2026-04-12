// Package session provides session management with cookie-based tracking and storage backends.
package session

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/soapbucket/sbproxy/internal/loader/manager"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// SessionService defines the interface for session service operations.
type SessionService interface {
	Save(context.Context, *reqctx.SessionData, time.Duration) error
	Get(context.Context, string) (*reqctx.SessionData, error)
	Delete(context.Context, string) error
	EncryptString(string) (string, error)
	DecryptString(string) (string, error)
}

type sessionServiceImpl struct {
	m manager.Manager
}

// Get retrieves session data from cache and decrypts it using a session-specific derived key
func (s *sessionServiceImpl) Get(ctx context.Context, sessionID string) (*reqctx.SessionData, error) {
	reader, err := s.m.GetSessionCache().Get(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	encryptedData, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	// Decrypt the session data using a key derived from the session ID
	// This ensures each session's data is encrypted with a unique key
	decryptedJSON, err := s.m.DecryptStringWithContext(string(encryptedData), sessionID)
	if err != nil {
		return nil, err
	}

	obj := &reqctx.SessionData{}
	if err := json.Unmarshal([]byte(decryptedJSON), obj); err != nil {
		return nil, err
	}
	return obj, nil
}

// Save encrypts and stores session data using a session-specific derived key
func (s *sessionServiceImpl) Save(ctx context.Context, session *reqctx.SessionData, expires time.Duration) error {
	jsonData, err := json.Marshal(session)
	if err != nil {
		return err
	}

	// Encrypt the session data using a key derived from the session ID
	// This ensures each session's data is encrypted with a unique key
	encryptedData, err := s.m.EncryptStringWithContext(string(jsonData), session.ID)
	if err != nil {
		return err
	}

	return s.m.GetSessionCache().Put(ctx, session.ID, bytes.NewReader([]byte(encryptedData)), expires)
}

// Delete performs the delete operation on the sessionServiceImpl.
func (s *sessionServiceImpl) Delete(ctx context.Context, sessionID string) error {
	return s.m.GetSessionCache().Delete(ctx, sessionID)
}

// EncryptString encrypts data using the master key (for session IDs in cookies)
func (s *sessionServiceImpl) EncryptString(data string) (string, error) {
	return s.m.EncryptString(data)
}

// DecryptString decrypts data using the master key (for session IDs in cookies)
func (s *sessionServiceImpl) DecryptString(data string) (string, error) {
	return s.m.DecryptString(data)
}

// NewSessionService creates and initializes a new SessionService.
func NewSessionService(m manager.Manager) SessionService {
	return &sessionServiceImpl{
		m: m,
	}
}
