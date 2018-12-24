package secrethub

import (
	"github.com/keylockerbv/secrethub-go/pkg/api"
	"github.com/keylockerbv/secrethub-go/pkg/crypto"
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

type serviceService struct {
	client *Client
}

// Create creates a new service for the given repo.
func (s *serviceService) Create(path api.RepoPath, description string, credential Credential) (*api.Service, error) {
	accountKey, err := generateAccountKey()
	if err != nil {
		return nil, errio.Error(err)
	}

	return s.client.CreateService(path, description, credential, accountKey)
}

// Delete removes a service.
func (s *serviceService) Delete(id string) (*api.RevokeRepoResponse, error) {
	return s.client.DeleteService(id)
}

// Get retrieves a service.
func (s *serviceService) Get(id string) (*api.Service, error) {
	return s.client.GetService(id)
}

// List is an alias of the RepoServiceService List function.
func (s *serviceService) List(path api.RepoPath) ([]*api.Service, error) {
	repoServiceService := &repoServiceService{s.client}
	return repoServiceService.List(path)
}

// CreateService creates a new service for the given repo.
func (c *Client) CreateService(repoPath api.RepoPath, description string, serviceCredential Credential, accountKey *crypto.RSAKey) (*api.Service, error) {
	credentialRequest, err := c.createCredentialRequest(serviceCredential)
	if err != nil {
		return nil, errio.Error(err)
	}

	accountKeyRequest, err := c.createAccountKeyRequest(serviceCredential, accountKey)
	if err != nil {
		return nil, errio.Error(err)
	}

	serviceRepoMemberRequest, err := c.createRepoMemberRequest(repoPath, accountKeyRequest.PublicKey)
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

	service, err := c.httpClient.CreateService(repoPath.GetNamespace(), repoPath.GetRepo(), in)
	if err != nil {
		return nil, errio.Error(err)
	}

	return service, nil
}

// GetService returns a service.
func (c *Client) GetService(serviceID string) (*api.Service, error) {
	err := api.ValidateServiceID(serviceID)
	if err != nil {
		return nil, errio.Error(err)
	}
	return c.httpClient.GetService(serviceID)
}

// DeleteService deletes a service.
func (c *Client) DeleteService(serviceID string) (*api.RevokeRepoResponse, error) {
	err := api.ValidateServiceID(serviceID)
	if err != nil {
		return nil, errio.Error(err)
	}

	resp, err := c.httpClient.DeleteService(serviceID)
	if err != nil {
		return nil, errio.Error(err)
	}

	return resp, nil
}
