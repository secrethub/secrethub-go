// +build !production

package fakeclient

import "github.com/keylockerbv/secrethub-go/pkg/api"

// RepoServiceService is a mock of the RepoServiceService interface.
type RepoServiceService struct {
	Lister RepoServiceLister
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
