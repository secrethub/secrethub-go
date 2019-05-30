// +build !production

package fakeclient

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/pkg/secrethub"
)

// AccountService is a mock of the AccountService interface.
type AccountService struct {
	Getter AccountGetter
}

// Get implements the AccountService interface Get function.
func (s *AccountService) Get(name string) (*api.Account, error) {
	return s.Getter.Get(name)
}

// AccountGetter mocks the Get function.
type AccountGetter struct {
	ArgName        string
	ReturnsAccount *api.Account
	Err            error
}

// Get saves the arguments it was called with and returns the mocked response.
func (g *AccountGetter) Get(name string) (*api.Account, error) {
	g.ArgName = name
	return g.ReturnsAccount, g.Err
}

// Keys implements the AccountService interface.
func (s *AccountService) Keys() secrethub.AccountKeyService {
	return nil
}
