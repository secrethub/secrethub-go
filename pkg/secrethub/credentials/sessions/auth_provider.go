package sessions

import (
	"net/http"

	httpclient "github.com/secrethub/secrethub-go/pkg/secrethub/internals/http"
)

func NewSessionRefresher(httpClient *httpclient.Client, sessionCreator SessionCreator) *SessionRefresher {
	return &SessionRefresher{
		httpClient:     httpClient,
		sessionCreator: sessionCreator,
	}
}

type SessionRefresher struct {
	httpClient     *httpclient.Client
	currentSession Session
	sessionCreator SessionCreator
}

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
