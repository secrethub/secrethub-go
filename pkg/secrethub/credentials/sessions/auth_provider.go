package sessions

import (
	"github.com/secrethub/secrethub-go/internals/auth"
	"github.com/secrethub/secrethub-go/pkg/secrethub/http"
)

func NewAuthProvider(sessionCreator SessionCreator) *AuthProvider {
	return &AuthProvider{
		sessionCreator: sessionCreator,
	}
}

type AuthProvider struct {
	currentSession Session
	sessionCreator SessionCreator
}

func (p *AuthProvider) Provide(httpClient *http.Client) (auth.Authenticator, error) {
	if p.currentSession == nil || p.currentSession.NeedsRefresh() {
		newSession, err := p.sessionCreator.Create(httpClient)
		if err != nil {
			return nil, err
		}
		p.currentSession = newSession
	}
	return p.currentSession.Authenticator(), nil
}
