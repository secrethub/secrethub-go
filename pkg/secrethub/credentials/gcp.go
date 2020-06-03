package credentials

import (
	"google.golang.org/api/option"

	"github.com/secrethub/secrethub-go/internals/auth"
	"github.com/secrethub/secrethub-go/internals/gcp"
	"github.com/secrethub/secrethub-go/pkg/secrethub/credentials/sessions"
	"github.com/secrethub/secrethub-go/pkg/secrethub/internals/http"
)

func UseGCPServiceAccount(gcpOptions ...option.ClientOption) Provider {
	return providerFunc(func(httpClient *http.Client) (auth.Authenticator, Decrypter, error) {
		decrypter, err := gcp.NewKMSDecrypter(gcpOptions...)
		if err != nil {
			return nil, nil, err
		}
		authenticator := sessions.NewSessionRefresher(httpClient, sessions.NewGCPSessionCreator(gcpOptions...))
		return authenticator, decrypter, nil
	})
}

type gcpServiceAccountCreator struct {
	keyResourceID       string
	serviceAccountEmail string

	gcpOptions []option.ClientOption

	credentialCreator *gcp.CredentialCreator
	metadata          map[string]string
}

func CreateGCPServiceAccount(serviceAccountEmail string, keyResourceID string, gcpOptions ...option.ClientOption) Creator {
	return &gcpServiceAccountCreator{
		keyResourceID:       keyResourceID,
		serviceAccountEmail: serviceAccountEmail,
		gcpOptions:          gcpOptions,
	}
}

func (gc *gcpServiceAccountCreator) Create() error {
	creator, metadata, err := gcp.NewCredentialCreator(gc.serviceAccountEmail, gc.keyResourceID, gc.gcpOptions...)
	if err != nil {
		return err
	}
	gc.metadata = metadata
	gc.credentialCreator = creator
	return nil
}

func (gc *gcpServiceAccountCreator) Verifier() Verifier {
	return gc.credentialCreator
}

func (gc *gcpServiceAccountCreator) Encrypter() Encrypter {
	return gc.credentialCreator
}

func (gc *gcpServiceAccountCreator) Metadata() map[string]string {
	return gc.metadata
}
