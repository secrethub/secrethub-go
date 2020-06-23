package secrethub

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/pkg/oauthorizer"
)

type IDPLinkService interface {
	GCP() IDPLinkGCPService
}

func newIDPLinkService(client *Client) IDPLinkService {
	return idpLinkService{
		client: client,
	}
}

type idpLinkService struct {
	client *Client
}

func (i idpLinkService) GCP() IDPLinkGCPService {
	return newIDPLinkGCPService(i.client)
}

type IDPLinkGCPService interface {
	Create(namespace string, projectID string, authorizationCode string, redirectURI string) (*api.IdentityProviderLink, error)
	List(namespace string) ([]*api.IdentityProviderLink, error)
	Get(namespace string, projectID string) (*api.IdentityProviderLink, error)
	Delete(namespace string, projectID string) error
	AuthorizationCodeListener() (oauthorizer.CallbackHandler, error)
}

func newIDPLinkGCPService(client *Client) IDPLinkGCPService {
	return idpLinkGCPService{
		client: client,
	}
}

type idpLinkGCPService struct {
	client *Client
}

func (i idpLinkGCPService) Create(namespace string, projectID string, authorizationCode, redirectURI string) (*api.IdentityProviderLink, error) {
	return i.client.httpClient.CreateIDPLink(namespace, api.IdentityProviderLinkGCP, projectID, &api.CreateIdentityProviderLinkGCPRequest{
		AuthorizationCode: authorizationCode,
		RedirectURL:       redirectURI,
	})
}

func (i idpLinkGCPService) List(namespace string) ([]*api.IdentityProviderLink, error) {
	return i.client.httpClient.ListIDPLinks(namespace, api.IdentityProviderLinkGCP)
}

func (i idpLinkGCPService) Get(namespace string, projectID string) (*api.IdentityProviderLink, error) {
	return i.client.httpClient.GetIDPLink(namespace, api.IdentityProviderLinkGCP, projectID)
}

func (i idpLinkGCPService) Delete(namespace string, projectID string) error {
	return i.client.httpClient.DeleteIDPLink(namespace, api.IdentityProviderLinkGCP, projectID)
}

func (i idpLinkGCPService) AuthorizationCodeListener() (oauthorizer.CallbackHandler, error) {
	oauthConfig, err := i.client.httpClient.GetGCPOAuthConfig()
	if err != nil {
		return oauthorizer.CallbackHandler{}, err
	}

	return oauthorizer.NewCallbackHandler(oauthConfig.Authorizer())
}
