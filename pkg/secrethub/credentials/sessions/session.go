// Package sessions provides session authentication to the SecretHub API for the HTTP client.
package sessions

import (
	"time"

	"github.com/secrethub/secrethub-go/internals/api/uuid"
	"github.com/secrethub/secrethub-go/internals/auth"
	"github.com/secrethub/secrethub-go/pkg/secrethub/internals/http"
)

const expirationMargin = time.Second * 30

// SessionCreator can create a new SecretHub session with a http.Client.
type SessionCreator interface {
	Create(httpClient *http.Client) (Session, error)
}

// Session provides a auth.Authenticator than can be temporarily used to temporarily authenticate to the SecretHub API.
type Session interface {
	NeedsRefresh() bool
	Authenticator() auth.Authenticator
}

type hmacSession struct {
	sessionID  uuid.UUID
	sessionKey string

	expireTime
}

// Authenticator returns an auth.Authenticator that can be used to authenticate a request with an HMAC session.
func (h hmacSession) Authenticator() auth.Authenticator {
	return auth.NewHTTPSigner(auth.NewSessionSigner(h.sessionID, h.sessionKey))
}

type expireTime time.Time

// NeedsRefresh returns true when the session is about to expire and should be refreshed.
func (t expireTime) NeedsRefresh() bool {
	return time.Time(t).After(time.Now().Add(expirationMargin))
}
