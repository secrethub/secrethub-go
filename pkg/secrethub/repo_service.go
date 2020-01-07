package secrethub

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/errio"
	"github.com/secrethub/secrethub-go/pkg/secrethub/iterator"
)

// RepoServiceService handles operations on services of repositories.
type RepoServiceService interface {
	// List lists the services of the given repository.
	List(path string) ([]*api.Service, error)
	// Iterator returns an iterator that lists all services of the given repository.
	Iterator(path string, _ *RepoServiceIteratorParams) ServiceIterator
}

func newRepoServiceService(client *Client) RepoServiceService {
	return &repoServiceService{
		client: client,
	}
}

type repoServiceService struct {
	client *Client
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

// Iterator returns an iterator that lists all services of the given repository.
func (s repoServiceService) Iterator(path string, _ *RepoServiceIteratorParams) ServiceIterator {
	return &serviceIterator{
		iterator: iterator.New(
			iterator.PaginatorFactory(
				func() ([]interface{}, error) {
					repoPath, err := api.NewRepoPath(path)
					if err != nil {
						return nil, errio.Error(err)
					}

					services, err := s.client.httpClient.ListServices(repoPath.GetNamespaceAndRepoName())
					if err != nil {
						return nil, errio.Error(err)
					}

					res := make([]interface{}, len(services))
					for i, element := range services {
						res[i] = element
					}
					return res, nil
				},
			),
		),
	}
}

// RepoServiceIteratorParams defines parameters used when listing Services of a given repo.
type RepoServiceIteratorParams struct{}
