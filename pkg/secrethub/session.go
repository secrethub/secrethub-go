package secrethub

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/secrethub/secrethub-go/internals/auth"
)

// SessionMethodService is an interface for any service that can provide authentication to the server.
type SessionMethodService interface {
	Create() (auth.Authenticator, error)
}

// SessionService handles authentication to the SecretHub API.
type SessionService interface {
	AWS(...*aws.Config) SessionMethodService
}

func newSessionService(client client) SessionService {
	return &sessionService{
		client: client,
	}
}

type sessionService struct {
	client client
}

// AWS returns an SessionMethodService for AWS.
func (s sessionService) AWS(awsCfg ...*aws.Config) SessionMethodService {
	return newAWSSessionService(s.client, awsCfg...)
}
