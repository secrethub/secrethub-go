package secrethub

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/secrethub/secrethub-go/internals/auth"
)

// AuthMethodService is an interface for any service that can provide authentication to the server.
type AuthMethodService interface {
	Authenticate() (auth.Authenticator, error)
}

// AuthService handles authentication to the SercretHub API.
type AuthService interface {
	AWS(...*aws.Config) AuthMethodService
}

func newAuthService(client client) AuthService {
	return &authService{
		client: client,
	}
}

type authService struct {
	client client
}

// Members returns an OrgMemberService.
func (s authService) AWS(awsCfg ...*aws.Config) AuthMethodService {
	return newAWSAuthService(s.client, awsCfg...)
}
