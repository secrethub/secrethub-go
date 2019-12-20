// +build !production

package fakeclient

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/pkg/secrethub"
)

// RepoServiceService is a mock of the RepoServiceService interface.
type RepoServiceService struct {
	Lister RepoServiceLister

	IteratorFunc func() secrethub.ServiceIterator
}

func (s *RepoServiceService) Iterator(path string, _ *secrethub.RepoServiceIteratorParams) secrethub.ServiceIterator {
	return s.IteratorFunc()
}

// List implements the RepoServiceService interface List function.
func (s *RepoServiceService) List(path string) ([]*api.Service, error) {
	return s.Lister.List(path)
}

// RepoServiceLister mocks the List function.
type RepoServiceLister struct {
	ArgPath         string
	ReturnsServices []*api.Service
	Err             error
}

// List saves the arguments it was called with and returns the mocked response.
func (l *RepoServiceLister) List(path string) ([]*api.Service, error) {
	l.ArgPath = path
	return l.ReturnsServices, l.Err
}
