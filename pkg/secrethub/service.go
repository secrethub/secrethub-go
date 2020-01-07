package secrethub

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/errio"
	"github.com/secrethub/secrethub-go/pkg/secrethub/credentials"
	"github.com/secrethub/secrethub-go/pkg/secrethub/iterator"
)

// ServiceService handles operations on service accounts from SecretHub.
type ServiceService interface {
	// Create creates a new service account for the given repo.
	Create(path string, description string, credential credentials.Creator) (*api.Service, error)
	// Get retrieves a service account by name.
	Get(name string) (*api.Service, error)
	// Delete removes a service account by name.
	Delete(name string) (*api.RevokeRepoResponse, error)
	// List lists all service accounts in a given repository.
	List(path string) ([]*api.Service, error)
	// Iterator returns an iterator that lists all service accounts in a given repository.
	Iterator(path string, _ *ServiceIteratorParams) ServiceIterator
}

func newServiceService(client *Client) ServiceService {
	return serviceService{
		client: client,
	}
}

type serviceService struct {
	client *Client
}

// Create creates a new service account for the given repo.
func (s serviceService) Create(path string, description string, credentialCreator credentials.Creator) (*api.Service, error) {
	repoPath, err := api.NewRepoPath(path)
	if err != nil {
		return nil, errio.Error(err)
	}

	err = api.ValidateServiceDescription(description)
	if err != nil {
		return nil, errio.Error(err)
	}

	err = credentialCreator.Create()
	if err != nil {
		return nil, err
	}

	accountKey, err := generateAccountKey()
	if err != nil {
		return nil, errio.Error(err)
	}

	credentialRequest, err := s.client.createCredentialRequest(credentialCreator.Verifier(), credentialCreator.Metadata())
	if err != nil {
		return nil, errio.Error(err)
	}

	accountKeyRequest, err := s.client.createAccountKeyRequest(credentialCreator.Encrypter(), accountKey)
	if err != nil {
		return nil, errio.Error(err)
	}

	serviceRepoMemberRequest, err := s.client.createRepoMemberRequest(repoPath, accountKeyRequest.PublicKey)
	if err != nil {
		return nil, errio.Error(err)
	}

	in := &api.CreateServiceRequest{
		Description: description,
		Credential:  credentialRequest,
		AccountKey:  accountKeyRequest,
		RepoMember:  serviceRepoMemberRequest,
	}

	err = in.Validate()
	if err != nil {
		return nil, errio.Error(err)
	}

	service, err := s.client.httpClient.CreateService(repoPath.GetNamespace(), repoPath.GetRepo(), in)
	if err != nil {
		return nil, errio.Error(err)
	}

	return service, nil
}

// Delete removes a service account.
func (s serviceService) Delete(name string) (*api.RevokeRepoResponse, error) {
	err := api.ValidateServiceID(name)
	if err != nil {
		return nil, errio.Error(err)
	}

	resp, err := s.client.httpClient.DeleteService(name)
	if err != nil {
		return nil, errio.Error(err)
	}

	return resp, nil
}

// Get retrieves a service account.
func (s serviceService) Get(name string) (*api.Service, error) {
	err := api.ValidateServiceID(name)
	if err != nil {
		return nil, errio.Error(err)
	}

	return s.client.httpClient.GetService(name)
}

// List is an alias of the RepoServiceService List function.
func (s serviceService) List(path string) ([]*api.Service, error) {
	repoServiceService := newRepoServiceService(s.client)
	return repoServiceService.List(path)
}

// Iterator returns an iterator that lists all service accounts in a given repository.
func (s serviceService) Iterator(path string, params *ServiceIteratorParams) ServiceIterator {
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

// ServiceIteratorParams defines parameters used when listing Services.
type ServiceIteratorParams struct{}

// ServiceIterator iterates over services.
type ServiceIterator interface {
	Next() (api.Service, error)
}

type serviceIterator struct {
	iterator iterator.Iterator
}

// Next returns the next service or iterator.Done as an error if all of them have been returned.
func (it *serviceIterator) Next() (api.Service, error) {
	item, err := it.iterator.Next()
	if err != nil {
		return api.Service{}, err
	}

	return item.(api.Service), nil
}
