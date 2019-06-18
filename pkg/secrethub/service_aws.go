package secrethub

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/aws"
)

// ServiceService handles operations on service accounts from SecretHub.
type ServiceAWSService interface {
	// Create creates a new service account for the given repo.
	Create(path string, description string, keyID, role string) (*api.Service, error)
}

func newServiceAWSService(client client, s ServiceService) ServiceAWSService {
	return serviceAWSService{
		client:         client,
		serviceService: s,
	}
}

type serviceAWSService struct {
	client         client
	serviceService ServiceService
}

// Create creates a new AWS service account for the given repo.
func (s serviceAWSService) Create(path string, description string, keyID, role string) (*api.Service, error) {
	creator, err := aws.NewServiceCreator(keyID, role)
	if err != nil {
		return nil, err
	}
	return s.serviceService.Create(path, description, creator, creator)
}
