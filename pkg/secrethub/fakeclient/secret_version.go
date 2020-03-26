// +build !production

package fakeclient

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/pkg/secrethub"
)

// SecretVersionService can be used to mock a SecretVersionService.
type SecretVersionService struct {
	DeleteFunc          func(path string) error
	GetWithDataFunc     func(path string) (*api.SecretVersion, error)
	GetWithoutDataFunc  func(path string) (*api.SecretVersion, error)
	ListWithDataFunc    func(path string) ([]*api.SecretVersion, error)
	ListWithoutDataFunc func(path string) ([]*api.SecretVersion, error)
	IteratorFunc        func(path string, params *secrethub.SecretVersionIteratorParams) secrethub.SecretVersionIterator
}

// Delete implements the SecretVersionService interface Delete function.
func (s *SecretVersionService) Delete(path string) error {
	return s.DeleteFunc(path)
}

// GetWithData implements the SecretVersionService interface GetWithData function.
func (s *SecretVersionService) GetWithData(path string) (*api.SecretVersion, error) {
	return s.GetWithDataFunc(path)
}

// GetWithoutData implements the SecretVersionService interface GetWithoutData function.
func (s *SecretVersionService) GetWithoutData(path string) (*api.SecretVersion, error) {
	return s.GetWithoutDataFunc(path)
}

// ListWithData implements the SecretVersionService interface ListWithData function.
func (s *SecretVersionService) ListWithData(path string) ([]*api.SecretVersion, error) {
	return s.ListWithDataFunc(path)
}

// ListWithoutData implements the SecretVersionService interface ListWithoutData function.
func (s *SecretVersionService) ListWithoutData(path string) ([]*api.SecretVersion, error) {
	return s.ListWithoutDataFunc(path)
}

func (s *SecretVersionService) Iterator(path string, params *secrethub.SecretVersionIteratorParams) secrethub.SecretVersionIterator {
	return s.IteratorFunc(path, params)
}
