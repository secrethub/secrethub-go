package secrethub

import (
	"github.com/keylockerbv/secrethub-go/pkg/api"
	"github.com/keylockerbv/secrethub-go/pkg/errio"
)

// ServiceService handles operations on service accounts from SecretHub.
type ServiceService interface {
	// Create creates a new service for the given repo.
	Create(path api.RepoPath, description string, credential Credential) (*api.Service, error)
	// Delete removes a service.
	Delete(id string) (*api.RevokeRepoResponse, error)
	// Get retrieves a service.
	Get(id string) (*api.Service, error)
	// List lists all services in a given repository.
	List(path api.RepoPath) ([]*api.Service, error)
}

func newServiceService(client client) ServiceService {
	return serviceService{
		client: client,
	}
}

type serviceService struct {
	client client
}

// Create creates a new service for the given repo.
func (s serviceService) Create(path api.RepoPath, description string, credential Credential) (*api.Service, error) {
	accountKey, err := generateAccountKey()
	if err != nil {
		return nil, errio.Error(err)
	}

	credentialRequest, err := s.client.createCredentialRequest(credential)
	if err != nil {
		return nil, errio.Error(err)
	}

	accountKeyRequest, err := s.client.createAccountKeyRequest(credential, accountKey)
	if err != nil {
		return nil, errio.Error(err)
	}

	serviceRepoMemberRequest, err := s.client.createRepoMemberRequest(path, accountKeyRequest.PublicKey)
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

	service, err := s.client.httpClient.CreateService(path.GetNamespace(), path.GetRepo(), in)
	if err != nil {
		return nil, errio.Error(err)
	}

	return service, nil
}

// Delete removes a service.
func (s serviceService) Delete(id string) (*api.RevokeRepoResponse, error) {
	err := api.ValidateServiceID(id)
	if err != nil {
		return nil, errio.Error(err)
	}

	resp, err := s.client.httpClient.DeleteService(id)
	if err != nil {
		return nil, errio.Error(err)
	}

	return resp, nil
}

// Get retrieves a service.
func (s serviceService) Get(id string) (*api.Service, error) {
	err := api.ValidateServiceID(id)
	if err != nil {
		return nil, errio.Error(err)
	}
	return s.client.httpClient.GetService(id)
}

// List is an alias of the RepoServiceService List function.
func (s serviceService) List(path api.RepoPath) ([]*api.Service, error) {
	repoServiceService := newRepoServiceService(s.client)
	return repoServiceService.List(path)
}
