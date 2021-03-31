// +build !production

package fakeclient

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/api/uuid"
	"github.com/secrethub/secrethub-go/pkg/secrethub"
)

// AccountService is a mock of the AccountService interface.
type AccountService struct {
	MeFunc            func() (*api.Account, error)
	DeleteFunc        func(accountID uuid.UUID) error
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

// Delete implements the AccountService interface Delete function.
func (s *AccountService) Delete(accountID uuid.UUID) error {
	return s.DeleteFunc(accountID)
}

// Me implements the AccountService interface Me function.
func (s *AccountService) Me() (*api.Account, error) {
	return s.MeFunc()
}
