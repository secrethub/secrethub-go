package fakeclient

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/oauthorizer"
	"github.com/secrethub/secrethub-go/pkg/secrethub"
)

type IDPLinkService struct {
	GCPFunc func() IDPLinkGCPService
}

func (i IDPLinkService) GCP() secrethub.IDPLinkGCPService {
	return i.GCPFunc()
}

type IDPLinkGCPService struct {
	CreateFunc                    func(namespace string, projectID string, authorizationCode string, redirectURI string) (*api.IdentityProviderLink, error)
	ListFunc                      func(namespace string, params *secrethub.IdpLinkIteratorParams) secrethub.IdpLinkIterator
	GetFunc                       func(namespace string, projectID string) (*api.IdentityProviderLink, error)
	ExistsFunc                    func(namespace string, projectID string) (bool, error)
	DeleteFunc                    func(namespace string, projectID string) error
	AuthorizationCodeListenerFunc func(namespace string, projectID string) (oauthorizer.CallbackHandler, error)
}

func (i IDPLinkGCPService) Create(namespace string, projectID string, authorizationCode, redirectURI string) (*api.IdentityProviderLink, error) {
	return i.CreateFunc(namespace, projectID, authorizationCode, redirectURI)
}

func (i IDPLinkGCPService) List(namespace string, params *secrethub.IdpLinkIteratorParams) secrethub.IdpLinkIterator {
	return i.ListFunc(namespace, params)
}

func (i IDPLinkGCPService) Get(namespace string, projectID string) (*api.IdentityProviderLink, error) {
	return i.GetFunc(namespace, projectID)
}

func (i IDPLinkGCPService) Exists(namespace string, projectID string) (bool, error) {
	return i.ExistsFunc(namespace, projectID)
}

func (i IDPLinkGCPService) Delete(namespace string, projectID string) error {
	return i.DeleteFunc(namespace, projectID)
}

func (i IDPLinkGCPService) AuthorizationCodeListener(namespace string, projectID string) (oauthorizer.CallbackHandler, error) {
	return i.AuthorizationCodeListenerFunc(namespace, projectID)
}
