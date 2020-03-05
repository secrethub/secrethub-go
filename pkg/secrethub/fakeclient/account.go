// +build !production

package fakeclient

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/pkg/secrethub"
)

// AccountService is a mock of the AccountService interface.
type AccountService struct {
	GetFunc           func(name string) (*api.Account, error)
	AccountKeyService secrethub.AccountKeyService
}

func (s *AccountService) Keys() secrethub.AccountKeyService {
	return s.AccountKeyService
}

// Get implements the AccountService interface Get function.
func (s *AccountService) Get(name string) (*api.Account, error) {
	return s.GetFunc(name)
}
