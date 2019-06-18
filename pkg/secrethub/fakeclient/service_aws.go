// +build !production

package fakeclient

import (
	"github.com/secrethub/secrethub-go/internals/api"
)

// ServiceAWSService is a mock of the ServiceAWSService interface.
type ServiceAWSService struct {
	Creater ServiceAWSCreater
}

// Create implements the ServiceAWSService interface Create function.
func (s *ServiceAWSService) Create(path string, description string, keyID, role string) (*api.Service, error) {
	return s.Creater.Create(path, description, keyID, role)
}

// ServiceCreater mocks the Create function.
type ServiceAWSCreater struct {
	ArgPath        string
	ArgDescription string
	ArgKeyID       string
	ArgRole        string
	ReturnsService *api.Service
	Err            error
}

// Create saves the arguments it was called with and returns the mocked response.
func (c *ServiceAWSCreater) Create(path string, description string, keyID, role string) (*api.Service, error) {
	c.ArgPath = path
	c.ArgDescription = description
	c.ArgKeyID = keyID
	c.ArgRole = role
	return c.ReturnsService, c.Err
}
