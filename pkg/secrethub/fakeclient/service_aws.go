// +build !production

package fakeclient

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/secrethub/secrethub-go/internals/api"
)

// ServiceAWSService is a mock of the ServiceAWSService interface.
type ServiceAWSService struct {
	Creator ServiceAWSCreater
}

// Create implements the ServiceAWSService interface Create function.
func (s *ServiceAWSService) Create(path string, description string, keyID, role string, cfgs ...*aws.Config) (*api.Service, error) {
	return s.Creator.Create(path, description, keyID, role, cfgs...)
}

// ServiceAWSCreater mocks the Create function.
type ServiceAWSCreater struct {
	ArgPath        string
	ArgDescription string
	ArgKeyID       string
	ArgRole        string
	Cfgs           []*aws.Config
	ReturnsService *api.Service
	Err            error
}

// Create saves the arguments it was called with and returns the mocked response.
func (c *ServiceAWSCreater) Create(path string, description string, keyID, role string, cfgs ...*aws.Config) (*api.Service, error) {
	c.ArgPath = path
	c.ArgDescription = description
	c.ArgKeyID = keyID
	c.ArgRole = role
	c.Cfgs = cfgs
	return c.ReturnsService, c.Err
}
