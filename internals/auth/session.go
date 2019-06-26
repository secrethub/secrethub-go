package auth

import (
	"github.com/secrethub/secrethub-go/internals/api/uuid"
	"github.com/secrethub/secrethub-go/internals/crypto"
)

// NewSessionSigner returns a new SessionSigner.
func NewSessionSigner(sessionID uuid.UUID, secretKey string) *SessionSigner {
	return &SessionSigner{
		sessionID: sessionID,
		secretKey: secretKey,
	}
}

// SessionSigner is an implementation of the Signer interface that uses an HMAC session to authenticate a request.
type SessionSigner struct {
	sessionID uuid.UUID
	secretKey string
}

// ID returns the session id of this signer.
func (s SessionSigner) ID() (string, error) {
	return s.sessionID.String(), nil
}

// SignMethod returns the signature method of this signer.
func (s SessionSigner) SignMethod() string {
	return "Session-HMAC"
}

// Sign the payload with an HMAC signature.
func (s SessionSigner) Sign(msg []byte) ([]byte, error) {
	key := crypto.NewSymmetricKey([]byte(s.secretKey))
	return key.HMAC(msg)
}
