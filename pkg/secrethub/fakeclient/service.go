// +build !production

package fakeclient

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/pkg/secrethub"
	"github.com/secrethub/secrethub-go/pkg/secrethub/credentials"
)

// ServiceService is a mock of the ServiceService interface.
type ServiceService struct {
	CreateFunc func(path string, description string, credentialCreator credentials.Creator) (*api.Service, error)
	DeleteFunc func(id string) (*api.RevokeRepoResponse, error)
	GetFunc    func(id string) (*api.Service, error)
	ListFunc   func(path string) ([]*api.Service, error)
	AWSService *ServiceAWSService

	IteratorFunc func() secrethub.ServiceIterator
}

func (s *ServiceService) Iterator(path string, _ *secrethub.ServiceIteratorParams) secrethub.ServiceIterator {
	return s.IteratorFunc()
}

// Create implements the ServiceService interface Create function.
func (s *ServiceService) Create(path string, description string, credentialCreator credentials.Creator) (*api.Service, error) {
	return s.CreateFunc(path, description, credentialCreator)
}

// Delete implements the ServiceService interface Delete function.
func (s *ServiceService) Delete(id string) (*api.RevokeRepoResponse, error) {
	return s.DeleteFunc(id)
}

// Get implements the ServiceService interface Get function.
func (s *ServiceService) Get(id string) (*api.Service, error) {
	return s.GetFunc(id)
}

// List implements the ServiceService interface List function.
func (s *ServiceService) List(path string) ([]*api.Service, error) {
	return s.ListFunc(path)
}
