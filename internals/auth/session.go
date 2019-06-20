package auth

import (
	"github.com/secrethub/secrethub-go/internals/api/uuid"
	"github.com/secrethub/secrethub-go/internals/crypto"
)

func NewSessionSigner(sessionID uuid.UUID, secretKey string) *SessionSigner {
	return &SessionSigner{
		sessionID: sessionID,
		secretKey: secretKey,
	}
}

type SessionSigner struct {
	sessionID uuid.UUID
	secretKey string
}

func (s SessionSigner) ID() (string, error) {
	return s.sessionID.String(), nil
}

func (s SessionSigner) SignMethod() string {
	return "Session"
}

func (s SessionSigner) Sign(msg []byte) ([]byte, error) {
	key := crypto.NewSymmetricKey([]byte(s.secretKey))
	return key.HMAC(msg)
}
