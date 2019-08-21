package sessions

import (
	"time"

	"github.com/secrethub/secrethub-go/internals/api/uuid"
	"github.com/secrethub/secrethub-go/internals/auth"
	"github.com/secrethub/secrethub-go/pkg/secrethub/internals/http"
)

const expirationMargin = time.Second * 30

type SessionCreator interface {
	Create(httpClient *http.Client) (Session, error)
}

type Session interface {
	NeedsRefresh() bool
	Authenticator() auth.Authenticator
}

type hmacSession struct {
	sessionID  uuid.UUID
	sessionKey string

	expireTime
}

func (h hmacSession) Authenticator() auth.Authenticator {
	return auth.NewHTTPSigner(auth.NewSessionSigner(h.sessionID, h.sessionKey))
}

type expireTime time.Time

func (t expireTime) NeedsRefresh() bool {
	return time.Time(t).After(time.Now().Add(expirationMargin))
}
