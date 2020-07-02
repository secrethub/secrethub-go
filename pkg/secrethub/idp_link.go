package secrethub

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/oauthorizer"
	"github.com/secrethub/secrethub-go/pkg/secrethub/iterator"
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
	List(namespace string, params *IdpLinkIteratorParams) IdpLinkIterator
	Get(namespace string, projectID string) (*api.IdentityProviderLink, error)
	Exists(namespace string, projectID string) (bool, error)
	Delete(namespace string, projectID string) error
	AuthorizationCodeListener(namespace string, projectID string) (oauthorizer.CallbackHandler, error)
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

// List returns an iterator that retrieves all GCP identity provider links for the given namespace.
//
// Usage:
//  iter := client.IDPLinks().GCP().List(namespace, &secrethub.IdpLinkIteratorParams{})
//  for {
//  	idpLink, err := iter.Next()
//  	if err == iterator.Done {
//  		break
//  	} else if err != nil {
//  		// Handle error
//  	}
//
//  	// Use identity provider link
//  }
func (i idpLinkGCPService) List(namespace string, params *IdpLinkIteratorParams) IdpLinkIterator {
	return &idpLinkIterator{
		iterator: iterator.New(
			iterator.PaginatorFactory(
				func() ([]interface{}, error) {
					idpLinks, err := i.client.httpClient.ListIDPLinks(namespace, api.IdentityProviderLinkGCP)
					if err != nil {
						return nil, err
					}

					res := make([]interface{}, len(idpLinks))
					for i, idpLink := range idpLinks {
						res[i] = idpLink
					}
					return res, nil
				},
			),
		),
	}
}

func (i idpLinkGCPService) Get(namespace string, projectID string) (*api.IdentityProviderLink, error) {
	return i.client.httpClient.GetIDPLink(namespace, api.IdentityProviderLinkGCP, projectID)
}

func (i idpLinkGCPService) Exists(namespace string, projectID string) (bool, error) {
	_, err := i.Get(namespace, projectID)
	if api.IsErrDisabled(err) {
		return true, nil
	} else if api.IsErrNotFound(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

func (i idpLinkGCPService) Delete(namespace string, projectID string) error {
	return i.client.httpClient.DeleteIDPLink(namespace, api.IdentityProviderLinkGCP, projectID)
}

func (i idpLinkGCPService) AuthorizationCodeListener(namespace string, projectID string) (oauthorizer.CallbackHandler, error) {
	oauthConfig, err := i.client.httpClient.GetGCPOAuthConfig()
	if err != nil {
		return oauthorizer.CallbackHandler{}, err
	}

	redirectURL := oauthConfig.RedirectURL
	q := redirectURL.Query()
	q.Set("namespace", namespace)
	q.Set("entity", projectID)
	redirectURL.RawQuery = q.Encode()

	authorizer := oauthorizer.NewAuthorizer(oauthConfig.AuthURI, oauthConfig.ClientID, oauthConfig.Scopes...)
	return oauthorizer.NewCallbackHandler(redirectURL, authorizer)
}

// IdpLinkIteratorParams defines parameters used when listing identity provider links.
type IdpLinkIteratorParams struct{}

// IdpLinkIterator iterates over identity provider links.
type IdpLinkIterator interface {
	Next() (api.IdentityProviderLink, error)
}

type idpLinkIterator struct {
	iterator iterator.Iterator
}

// Next returns the next identity provider link or iterator.Done as an error if all of them have been returned.
func (it *idpLinkIterator) Next() (api.IdentityProviderLink, error) {
	item, err := it.iterator.Next()
	if err != nil {
		return api.IdentityProviderLink{}, err
	}

	return *item.(*api.IdentityProviderLink), nil
}
