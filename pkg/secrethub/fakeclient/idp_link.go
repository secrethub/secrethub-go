package fakeclient

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/oauthorizer"
	"github.com/secrethub/secrethub-go/pkg/secrethub"
)

type IDPLinkService struct {
	CreateFunc                    func(namespace string, projectID string, authorizationCode string, redirectURI string) (*api.IdentityProviderLink, error)
	ListFunc                      func(namespace string, params *secrethub.IdpLinkIteratorParams) secrethub.IdpLinkIterator
	GetFunc                       func(namespace string, projectID string) (*api.IdentityProviderLink, error)
	ExistsFunc                    func(namespace string, projectID string) (bool, error)
	DeleteFunc                    func(namespace string, projectID string) error
	AuthorizationCodeListenerFunc func(namespace string, projectID string) (oauthorizer.CallbackHandler, error)
	secrethub.IDPLinkService
}

func (i *IDPLinkService) Create(namespace string, projectID string, authorizationCode, redirectURI string) (*api.IdentityProviderLink, error) {
	return i.CreateFunc(namespace, projectID, authorizationCode, redirectURI)
}

func (i *IDPLinkService) List(namespace string, params *secrethub.IdpLinkIteratorParams) secrethub.IdpLinkIterator {
	return i.ListFunc(namespace, params)
}

func (i *IDPLinkService) Get(namespace string, projectID string) (*api.IdentityProviderLink, error) {
	return i.GetFunc(namespace, projectID)
}

func (i *IDPLinkService) Exists(namespace string, projectID string) (bool, error) {
	return i.ExistsFunc(namespace, projectID)
}

func (i *IDPLinkService) Delete(namespace string, projectID string) error {
	return i.DeleteFunc(namespace, projectID)
}

func (i *IDPLinkService) AuthorizationCodeListener(namespace string, projectID string) (oauthorizer.CallbackHandler, error) {
	return i.AuthorizationCodeListenerFunc(namespace, projectID)
}
