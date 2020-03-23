// +build !production

package fakeclient

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/secrethub/secrethub-go/internals/api"
)

// ServiceAWSService is a mock of the ServiceAWSService interface.
type ServiceAWSService struct {
	CreateFunc func(path string, description string, keyID, role string, cfgs ...*aws.Config) (*api.Service, error)
}

// Create implements the ServiceAWSService interface Create function.
func (s *ServiceAWSService) Create(path string, description string, keyID, role string, cfgs ...*aws.Config) (*api.Service, error) {
	return s.CreateFunc(path, description, keyID, role, cfgs...)
}
