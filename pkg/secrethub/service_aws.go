package secrethub

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/aws"

	awssdk "github.com/aws/aws-sdk-go/aws"
)

// ServiceAWSService handles operations on service accounts from SecretHub.
type ServiceAWSService interface {
	// Create creates a new service account for the given repo.
	Create(path string, description string, keyID, role string, cfgs ...*awssdk.Config) (*api.Service, error)
}

func newServiceAWSService(client *Client, s ServiceService) ServiceAWSService {
	return serviceAWSService{
		client:         client,
		serviceService: s,
	}
}

type serviceAWSService struct {
	client         *Client
	serviceService ServiceService
}

// Create creates a new AWS service account for the given repo.
func (s serviceAWSService) Create(path string, description string, keyID, role string, cfgs ...*awssdk.Config) (*api.Service, error) {
	creator, err := aws.NewServiceCreator(keyID, role, cfgs...)
	if err != nil {
		return nil, err
	}
	return s.serviceService.Create(path, description, creator, creator)
}
