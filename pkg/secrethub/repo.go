package secrethub

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/crypto"
	"github.com/secrethub/secrethub-go/internals/errio"
	"github.com/secrethub/secrethub-go/pkg/secrethub/internals/http"
	"github.com/secrethub/secrethub-go/pkg/secrethub/iterator"
)

// RepoService handles operations on repositories from SecretHub.
type RepoService interface {
	// Create creates a new repo for the given owner and name.
	Create(path string) (*api.Repo, error)
	// Get retrieves the repo with the given path.
	Get(path string) (*api.Repo, error)
	// Delete removes the repo with the given path.
	Delete(path string) error
	// List retrieves all repositories in the given namespace.
	List(namespace string) ([]*api.Repo, error)
	// Iterator returns a new iterator that retrieves all repos in the given namespace.
	Iterator(namespace string, _ *RepoIteratorParams) RepoIterator
	// ListAccounts lists the accounts in the repository.
	ListAccounts(path string) ([]*api.Account, error)
	// AccountIterator returns a new iterator that retrieves all accounts in the given namespace.
	AccountIterator(namespace string, params *RepoIteratorParams) AccountIterator
	// EventIterator returns an iterator that retrieves all audit events for a given repo.
	//
	// Usage:
	//  iter := client.Repos().EventIterator(path, &secrethub.AuditEventIteratorParams{})
	//  for {
	//  	event, err := iter.Next()
	//  	if err == iterator.Done {
	//  		break
	//  	} else if err != nil {
	//  		// Handle error
	//  	}
	//
	//  	// Use event
	//  }
	EventIterator(path string, _ *AuditEventIteratorParams) AuditEventIterator
	// ListEvents retrieves all audit events for a given repo.
	ListEvents(path string, subjectTypes api.AuditSubjectTypeList) ([]*api.Audit, error)
	// ListMine retrieves all repositories of the current user.
	ListMine() ([]*api.Repo, error)
	// IteratorMine returns an iterator that retrieves all repos of the current user.
	IteratorMine(_ *RepoIteratorParams) RepoIterator
	// Users returns a RepoUserService that handles operations on users of a repository.
	Users() RepoUserService
	// Services returns a RepoServiceService that handles operations on services of a repository.
	Services() RepoServiceService
}

func newRepoService(client *Client) RepoService {
	return repoService{
		client: client,
	}
}

type repoService struct {
	client *Client
}

// Delete removes the repo with the given path.
func (s repoService) Delete(path string) error {
	repoPath, err := api.NewRepoPath(path)
	if err != nil {
		return errio.Error(err)
	}

	err = s.client.httpClient.DeleteRepo(repoPath.GetNamespaceAndRepoName())
	if err != nil {
		return errio.Error(err)
	}

	delete(s.client.repoIndexKeys, repoPath)

	return nil
}

// Get retrieves the repo with the given path.
func (s repoService) Get(path string) (*api.Repo, error) {
	repoPath, err := api.NewRepoPath(path)
	if err != nil {
		return nil, errio.Error(err)
	}

	return s.client.httpClient.GetRepo(repoPath.GetNamespaceAndRepoName())
}

// List retrieves all repositories in the given namespace.
func (s repoService) List(namespace string) ([]*api.Repo, error) {
	err := api.ValidateNamespace(namespace)
	if err != nil {
		return nil, errio.Error(err)
	}

	return s.client.httpClient.ListRepos(namespace)
}

// ListAccounts lists the accounts in the repository.
func (s repoService) ListAccounts(path string) ([]*api.Account, error) {
	repoPath, err := api.NewRepoPath(path)
	if err != nil {
		return nil, errio.Error(err)
	}

	return s.client.httpClient.ListRepoAccounts(repoPath.GetNamespaceAndRepoName())
}

// ListEvents retrieves all audit events for a given repo.
// If subjectTypes is left empty, the server's default is used.
func (s repoService) ListEvents(path string, subjectTypes api.AuditSubjectTypeList) ([]*api.Audit, error) {
	repoPath, err := api.NewRepoPath(path)
	if err != nil {
		return nil, errio.Error(err)
	}

	namespace, repoName := repoPath.GetNamespaceAndRepoName()
	events, err := s.client.httpClient.AuditRepo(namespace, repoName, subjectTypes)
	if err != nil {
		return nil, errio.Error(err)
	}

	err = s.client.decryptAuditEvents(events...)
	if err != nil {
		return nil, errio.Error(err)
	}

	return events, nil
}

// EventIterator returns an iterator that retrieves all audit events for a given repo.
//
// Usage:
//  iter := client.Repos().EventIterator(path, &secrethub.AuditEventIteratorParams{})
//  for {
//  	event, err := iter.Next()
//  	if err == iterator.Done {
//  		break
//  	} else if err != nil {
//  		// Handle error
//  	}
//
//  	// Use event
//  }
func (s repoService) EventIterator(path string, _ *AuditEventIteratorParams) AuditEventIterator {
	return newAuditEventIterator(
		func() (*http.AuditPaginator, error) {
			repoPath, err := api.NewRepoPath(path)
			if err != nil {
				return nil, err
			}

			namespace, repoName := repoPath.GetNamespaceAndRepoName()
			return s.client.httpClient.AuditRepoPaginator(namespace, repoName), nil
		},
		s.client,
	)
}

// ListMine retrieves all repositories of the current user.
func (s repoService) ListMine() ([]*api.Repo, error) {
	return s.client.httpClient.ListMyRepos()
}

// Create creates a new repo for the given owner and name.
func (s repoService) Create(path string) (*api.Repo, error) {
	repoPath, err := api.NewRepoPath(path)
	if err != nil {
		return nil, errio.Error(err)
	}

	account, err := s.client.getMyAccount()
	if err != nil {
		return nil, errio.Error(err)
	}

	accountKey, err := s.client.getAccountKey()
	if err != nil {
		return nil, errio.Error(err)
	}

	// Generate the repoEncryptionKey and wrap it.
	key, err := crypto.GenerateSymmetricKey()
	if err != nil {
		return nil, errio.Error(err)
	}
	repoEncryptionKey, err := accountKey.Public().WrapBytes(key.Export())
	if err != nil {
		return nil, errio.Error(err)
	}

	// Generate repoIndexKey, repoBlindName and wrap it.
	key, err = crypto.GenerateSymmetricKey()
	if err != nil {
		return nil, errio.Error(err)
	}

	repoIndexKey, err := accountKey.Public().WrapBytes(key.Export())
	if err != nil {
		return nil, errio.Error(err)
	}

	// Generate the Root Dir with a DirMember for yourself only.
	encryptedNames, err := encryptNameForAccounts(repoPath.GetRepo(), account)
	if err != nil {
		return nil, errio.Error(err)
	}

	blindName, err := repoPath.BlindName(key)
	if err != nil {
		return nil, errio.Error(err)
	}

	parentBlindName := blindName

	rootDir := &api.CreateDirRequest{
		BlindName:       blindName,
		ParentBlindName: parentBlindName,

		EncryptedNames: encryptedNames,
	}

	in := &api.CreateRepoRequest{
		Name:    repoPath.GetRepo(),
		RootDir: rootDir,
		RepoMember: &api.CreateRepoMemberRequest{
			RepoEncryptionKey: repoEncryptionKey,
			RepoIndexKey:      repoIndexKey,
		},
	}

	err = in.Validate()
	if err != nil {
		return nil, errio.Error(err)
	}

	repo, err := s.client.httpClient.CreateRepo(repoPath.GetNamespace(), in)
	if err != nil {
		return nil, errio.Error(err)
	}

	return repo, nil
}

// Users returns a RepoUserService that handles operations on users of a repository.
func (s repoService) Users() RepoUserService {
	return newRepoUserService(s.client)
}

// Services returns a RepoServiceService that handles operations on services of a repository.
func (s repoService) Services() RepoServiceService {
	return newRepoServiceService(s.client)
}

// Creates a new RepoMemberRequests for a given account.
func (c *Client) createRepoMemberRequest(repoPath api.RepoPath, accountPublicKey []byte) (*api.CreateRepoMemberRequest, error) {
	repoKey, err := c.httpClient.GetRepoKeys(repoPath.GetNamespaceAndRepoName())
	if err != nil {
		return nil, errio.Error(err)
	}

	accountKey, err := c.getAccountKey()
	if err != nil {
		return nil, errio.Error(err)
	}

	rsaPublicKey, err := crypto.ImportRSAPublicKey(accountPublicKey)
	if err != nil {
		return nil, errio.Error(err)
	}

	accountRepoEncryptionKey, err := accountKey.ReWrapBytes(rsaPublicKey, repoKey.RepoEncryptionKey)
	if err != nil {
		return nil, errio.Error(err)
	}

	accountRepoIndexKey, err := accountKey.ReWrapBytes(rsaPublicKey, repoKey.RepoIndexKey)
	if err != nil {
		return nil, errio.Error(err)
	}

	return &api.CreateRepoMemberRequest{
		RepoEncryptionKey: accountRepoEncryptionKey,
		RepoIndexKey:      accountRepoIndexKey,
	}, nil
}

// getRepoIndexKey retrieves a RepoIndexKey for a repo.
// These keys are cached in the client.
func (c *Client) getRepoIndexKey(repoPath api.RepoPath) (*crypto.SymmetricKey, error) {
	repoIndexKey, cached := c.repoIndexKeys[repoPath]
	if cached {
		return repoIndexKey, nil
	}

	wrappedKey, err := c.httpClient.GetRepoKeys(repoPath.GetNamespaceAndRepoName())
	if err != nil {
		return nil, errio.Error(err)
	}

	accountKey, err := c.getAccountKey()
	if err != nil {
		return nil, errio.Error(err)
	}

	keyData, err := accountKey.UnwrapBytes(wrappedKey.RepoIndexKey)
	if err != nil {
		return nil, errio.Error(err)
	}

	repoIndexKey = crypto.NewSymmetricKey(keyData)

	c.repoIndexKeys[repoPath] = repoIndexKey

	return repoIndexKey, nil
}

// Iterator returns a new iterator that retrieves all repos in the given namespace.
func (s repoService) Iterator(namespace string, params *RepoIteratorParams) RepoIterator {
	return &repoIterator{
		iterator: iterator.New(
			iterator.PaginatorFactory(
				func() ([]interface{}, error) {
					repos, err := s.List(namespace)
					if err != nil {
						return nil, err
					}

					res := make([]interface{}, len(repos))
					for i, element := range repos {
						res[i] = element
					}
					return res, nil
				},
			),
		),
	}
}

// IteratorMine returns an iterator that retrieves all repos of the current user.
func (s repoService) IteratorMine(_ *RepoIteratorParams) RepoIterator {
	return &repoIterator{
		iterator: iterator.New(
			iterator.PaginatorFactory(
				func() ([]interface{}, error) {
					repos, err := s.ListMine()
					if err != nil {
						return nil, err
					}

					res := make([]interface{}, len(repos))
					for i, element := range repos {
						res[i] = element
					}
					return res, nil
				},
			),
		),
	}
}

// AccountIterator returns a new iterator that retrieves all accounts in the given namespace.
func (s repoService) AccountIterator(namespace string, params *RepoIteratorParams) AccountIterator {
	return &accountIterator{
		iterator: iterator.New(
			iterator.PaginatorFactory(
				func() ([]interface{}, error) {
					accounts, err := s.ListAccounts(namespace)
					if err != nil {
						return nil, err
					}

					res := make([]interface{}, len(accounts))
					for i, element := range accounts {
						res[i] = element
					}
					return res, nil
				},
			),
		),
	}
}

// RepoIteratorParams defines parameters used when listing repos.
type RepoIteratorParams struct{}

// RepoIterator iterates over repositories.
type RepoIterator interface {
	Next() (api.Repo, error)
}

type repoIterator struct {
	iterator iterator.Iterator
}

// Next returns the next repo or iterator.Done as an error if all of them have been returned.
func (it *repoIterator) Next() (api.Repo, error) {
	item, err := it.iterator.Next()
	if err != nil {
		return api.Repo{}, err
	}

	return item.(api.Repo), nil
}

// AccountIteratorParams defines parameters used when listing Accounts.
type AccountIteratorParams struct{}

// AccountIterator iterates over accounts.
type AccountIterator interface {
	Next() (api.Account, error)
}

type accountIterator struct {
	iterator iterator.Iterator
}

// Next returns the next account or iterator.Done as an error if all of them have been returned.
func (it *accountIterator) Next() (api.Account, error) {
	item, err := it.iterator.Next()
	if err != nil {
		return api.Account{}, err
	}

	return item.(api.Account), nil
}
