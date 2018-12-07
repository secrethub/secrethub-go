package secrethub

import "github.com/keylockerbv/secrethub-go/pkg/api"

// RepoServiceService handles operations on services of repositories.
type RepoServiceService interface {
	// List lists the services of the given repository.
	List(path api.RepoPath) ([]*api.Service, error)
}

type repoServiceService struct {
	client *Client
}

// List lists the services of the given repository.
func (s repoServiceService) List(path api.RepoPath) ([]*api.Service, error) {
	return s.client.ListRepoServices(path)
}
