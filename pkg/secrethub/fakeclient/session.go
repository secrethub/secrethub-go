// +build !production

package fakeclient

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/secrethub/secrethub-go/internals/auth"
	"github.com/secrethub/secrethub-go/pkg/secrethub"
)

// SessionService is a mock of the SessionService interface.
type SessionService struct {
	secrethub.SessionMethodService
}

// AWS returns the SessionMethodService.
func (g *SessionService) AWS(...*aws.Config) secrethub.SessionMethodService {
	return g.SessionMethodService
}

// SessionMethod is a mock of the SessionMethodService interface.
type SessionMethod struct {
	err  error
	auth auth.Authenticator
}

// Create mocks the Create function.
func (a SessionMethod) Create() (auth.Authenticator, error) {
	return a.auth, a.err
}
