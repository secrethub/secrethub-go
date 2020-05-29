package sessions

import (
	"errors"

	"cloud.google.com/go/compute/metadata"
	"google.golang.org/api/option"

	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/gcp"
	"github.com/secrethub/secrethub-go/pkg/secrethub/internals/http"
)

type gcpSessionCreator struct {
	gcpOptions []option.ClientOption
}

// NewAWSSessionCreator returns a SessionCreator that uses a GCP Service Account Identity Token to request sessions.
func NewGCPSessionCreator(gcpOptions ...option.ClientOption) SessionCreator {
	return &gcpSessionCreator{
		gcpOptions: gcpOptions,
	}
}

// Create a new Session using GCP Service Account Identity Token for authentication.
func (s *gcpSessionCreator) Create(httpClient *http.Client) (Session, error) {
	if !metadata.OnGCE() {
		return nil, errors.New("GCP Identity Provider only supported when running on GCP")

	}
	idToken, err := metadata.Get("instance/service-accounts/default/identity?audience=secrethub&format=full")
	if err != nil {
		return nil, gcp.HandleError(err)
	}

	req := api.NewAuthRequestGCPServiceAccount(api.SessionTypeHMAC, idToken)
	resp, err := httpClient.CreateSession(req)
	if err != nil {
		return nil, err
	}
	if resp.Type != api.SessionTypeHMAC {
		return nil, api.ErrInvalidSessionType
	}
	sess := resp.HMAC()

	return &hmacSession{
		sessionID:  sess.SessionID,
		sessionKey: sess.Payload.SessionKey,
		expireTime: expireTime(sess.Expires),
	}, nil
}
