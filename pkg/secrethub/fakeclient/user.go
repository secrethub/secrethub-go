// +build !production

package fakeclient

import (
	"github.com/secrethub/secrethub-go/internals/api"
)

// UserService is a mock of the UserService interface.
type UserService struct {
	GetFunc func(username string) (*api.User, error)
	MeFunc  func() (*api.User, error)
}

// Get implements the UserService interface Get function.
func (s *UserService) Get(username string) (*api.User, error) {
	return s.GetFunc(username)
}

// Me implements the UserService interface Me function.
func (s *UserService) Me() (*api.User, error) {
	return s.MeFunc()
}
