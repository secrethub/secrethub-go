package secrethub

import (
	"github.com/keylockerbv/secrethub-go/pkg/api"
	"github.com/keylockerbv/secrethub-go/internals/errio"
)

// RepoServiceService handles operations on services of repositories.
type RepoServiceService interface {
	// List lists the services of the given repository.
	List(path string) ([]*api.Service, error)
}

func newRepoServiceService(client client) RepoServiceService {
	return &repoServiceService{
		client: client,
	}
}

type repoServiceService struct {
	client client
}

// List lists the services of the given repository.
func (s repoServiceService) List(path string) ([]*api.Service, error) {
	repoPath, err := api.NewRepoPath(path)
	if err != nil {
		return nil, errio.Error(err)
	}

	services, err := s.client.httpClient.ListServices(repoPath.GetNamespaceAndRepoName())
	if err != nil {
		return nil, errio.Error(err)
	}

	return services, nil
}
