// +build !production

package fakeclient

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/pkg/secrethub"
)

// RepoServiceService is a mock of the RepoServiceService interface.
type RepoServiceService struct {
	ListFunc func(path string) ([]*api.Service, error)
	IteratorFunc func() secrethub.ServiceIterator
}

func (s *RepoServiceService) Iterator(path string, _ *secrethub.RepoServiceIteratorParams) secrethub.ServiceIterator {
	return s.IteratorFunc()
}

// List implements the RepoServiceService interface List function.
func (s *RepoServiceService) List(path string) ([]*api.Service, error) {
	return s.ListFunc(path)
}