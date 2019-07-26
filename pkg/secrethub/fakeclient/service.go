// +build !production

package fakeclient

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/pkg/secrethub"
)

// ServiceService is a mock of the ServiceService interface.
type ServiceService struct {
	Creator    ServiceCreater
	Deleter    ServiceDeleter
	Getter     ServiceGetter
	Lister     RepoServiceLister
	AWSService *ServiceAWSService
}

// Create implements the ServiceService interface Create function.
func (s *ServiceService) Create(path string, description string, credential secrethub.Verifier, encrypter secrethub.Encrypter) (*api.Service, error) {
	return s.Creator.Create(path, description, credential, encrypter)
}

// Delete implements the ServiceService interface Delete function.
func (s *ServiceService) Delete(id string) (*api.RevokeRepoResponse, error) {
	return s.Deleter.Delete(id)
}

// Get implements the ServiceService interface Get function.
func (s *ServiceService) Get(id string) (*api.Service, error) {
	return s.Getter.Get(id)
}

// List implements the ServiceService interface List function.
func (s *ServiceService) List(path string) ([]*api.Service, error) {
	return s.Lister.List(path)
}

// AWS implements the ServiceService interface AWS function.
func (s *ServiceService) AWS() secrethub.ServiceAWSService {
	return s.AWSService
}

// ServiceCreater mocks the Create function.
type ServiceCreater struct {
	ArgPath        string
	ArgDescription string
	ArgCredential  secrethub.Verifier
	ReturnsService *api.Service
	Err            error
}

// Create saves the arguments it was called with and returns the mocked response.
func (c *ServiceCreater) Create(path string, description string, credential secrethub.Verifier, encrypter secrethub.Encrypter) (*api.Service, error) {
	c.ArgPath = path
	c.ArgDescription = description
	c.ArgCredential = credential
	return c.ReturnsService, c.Err
}

// ServiceDeleter mocks the Delete function.
type ServiceDeleter struct {
	ArgID                 string
	ReturnsRevokeResponse *api.RevokeRepoResponse
	Err                   error
}

// Delete saves the arguments it was called with and returns the mocked response.
func (d *ServiceDeleter) Delete(id string) (*api.RevokeRepoResponse, error) {
	d.ArgID = id
	return d.ReturnsRevokeResponse, d.Err
}

// ServiceGetter mocks the Get function.
type ServiceGetter struct {
	ArgID          string
	ReturnsService *api.Service
	Err            error
}

// Get saves the arguments it was called with and returns the mocked response.
func (g *ServiceGetter) Get(id string) (*api.Service, error) {
	g.ArgID = id
	return g.ReturnsService, g.Err
}
