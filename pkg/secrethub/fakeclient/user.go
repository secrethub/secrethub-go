// +build !production

package fakeclient

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/pkg/secrethub/credentials"
)

// UserService is a mock of the UserService interface.
type UserService struct {
	GetFunc    func(username string) (*api.User, error)
	MeFunc     func() (*api.User, error)
	CreateFunc func(username, email, fullName string, credentialCreator credentials.Creator, acceptToS bool) (*api.User, error)
}

// Get implements the UserService interface Get function.
func (s *UserService) Get(username string) (*api.User, error) {
	return s.GetFunc(username)
}

// Me implements the UserService interface Me function.
func (s *UserService) Me() (*api.User, error) {
	return s.MeFunc()
}

// Create implements the UserService interface Create function.
func (s *UserService) Create(username, email, fullName string, credentialCreator credentials.CreatorProvider, acceptToS bool) (*api.User, error) {
	return s.CreateFunc(username, email, fullName, credentialCreator, acceptToS)
}
