// +build !production

package fakeclient

import (
	"github.com/secrethub/secrethub-go/internals/auth"
	"github.com/secrethub/secrethub-go/pkg/secrethub"
)

// AuthService is a mock of the AuthService interface.
type AuthService struct {
	secrethub.AuthMethodService
}

// AWS returns the AuthMethodService.
func (g *AuthService) AWS() secrethub.AuthMethodService {
	return g.AuthMethodService
}

// AuthMethod is a mock of the AuthMethodService interface.
type AuthMethod struct {
	err  error
	auth auth.Authenticator
}

// Authenticate mocks the Authenticate function.
func (a AuthMethod) Authenticate() (auth.Authenticator, error) {
	return a.auth, a.err
}
