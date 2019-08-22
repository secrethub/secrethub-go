package sessions

import (
	"net/http"

	httpclient "github.com/secrethub/secrethub-go/pkg/secrethub/internals/http"
)

// SessionRefresher implements auth.Authenticator by using sessions for authentication that are automatically
// refreshed when they are about to expire.
type SessionRefresher struct {
	httpClient     *httpclient.Client
	currentSession Session
	sessionCreator SessionCreator
}

// NewSessionRefresher creates a new SessionRefresher that uses the httpClient for requesting new sessions with
// the SessionCreator.
func NewSessionRefresher(httpClient *httpclient.Client, sessionCreator SessionCreator) *SessionRefresher {
	return &SessionRefresher{
		httpClient:     httpClient,
		sessionCreator: sessionCreator,
	}
}

// Authenticate the given request with a session that is automatically refreshed when in almost expires.
func (r *SessionRefresher) Authenticate(req *http.Request) error {
	if r.currentSession == nil || r.currentSession.NeedsRefresh() {
		newSession, err := r.sessionCreator.Create(r.httpClient)
		if err != nil {
			return err
		}
		r.currentSession = newSession
	}
	return r.currentSession.Authenticator().Authenticate(req)
}
