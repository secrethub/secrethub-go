// +build !production

package fakeclient

import (
	"github.com/keylockerbv/secrethub-go/pkg/api"
	"github.com/keylockerbv/secrethub-go/pkg/secrethub"
)

// AccountService is a mock of the AccountService interface.
type AccountService struct {
	GetFunc func(name api.AccountName) (*api.Account, error)
}

// Get implements the AccountService interface Get function.
func (s AccountService) Get(name api.AccountName) (*api.Account, error) {
	return s.GetFunc(name)
}

// Keys implements the AccountService interface.
func (s AccountService) Keys() secrethub.AccountKeyService {
	return nil
}
