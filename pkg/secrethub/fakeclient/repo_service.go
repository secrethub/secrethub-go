// +build !production

package fakeclient

import "github.com/keylockerbv/secrethub-go/pkg/api"

// RepoServiceService is a mock of the RepoServiceService interface.
type RepoServiceService struct {
	ListFunc func(path api.RepoPath) ([]*api.Service, error)
}

// List implements the RepoServiceService interface List function.
func (s RepoServiceService) List(path api.RepoPath) ([]*api.Service, error) {
	return s.ListFunc(path)
}
