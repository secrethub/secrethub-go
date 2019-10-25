package secrethub

import (
	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/crypto"
	"github.com/secrethub/secrethub-go/internals/errio"
	"github.com/secrethub/secrethub-go/pkg/secrethub/internals/http"
)

// RepoService handles operations on repositories from SecretHub.
type RepoService interface {
	// Create creates a new repo for the given owner and name.
	Create(path string) (*api.Repo, error)
	// Delete removes the repo with the given path.
	Delete(path string) error
	// Get retrieves the repo with the given path.
	Get(path string) (*api.Repo, error)
	// EventIterator returns an iterator that retrieves all audit events for a given repo.
	//
	// Usage:
	//  it, err := client.Repos().EventIterator(path)
	//  if err != nil {
	//  	   // Handle error
	//  }
	//  for {
	//      event, err := events.Next()
	//	    if err == secrethub.IteratorDone {
	//	        break
	//	    }
	//	    if err != nil {
	//	        // Handle error
	//	    }
	//
	//      // Use event
	//  }
	EventIterator(path string, options ...AuditEventIterationOption) (AuditEventIterator, error)
	// List retrieves all repositories in the given namespace.
	List(namespace string) ([]*api.Repo, error)
	// ListAccounts lists the accounts in the repository.
	ListAccounts(path string) ([]*api.Account, error)
	// ListEvents retrieves all audit events for a given repo.
	//
	// Deprecated: Use `EventIterator` instead.
	ListEvents(path string, subjectTypes api.AuditSubjectTypeList) ([]*api.Audit, error)
	// ListMine retrieves all repositories of the current user.
	ListMine() ([]*api.Repo, error)
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
//
// Deprecated: Use `EventIterator` instead.
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

type AuditEventIterationOption func(*AuditEventIterator) error

func OnlySubjectTypes(subjectTypes api.AuditSubjectTypeList) AuditEventIterationOption {
	return func(it *AuditEventIterator) error {
		return http.OnlySubjectTypes(subjectTypes)(it.paginator)
	}
}

// EventIterator returns an iterator that retrieves all audit events for a given repo.
//
// Usage:
//  it, err := client.Repos().EventIterator(path)
//  if err != nil {
//  	   // Handle error
//  }
//  for {
//      event, err := events.Next()
//	    if err == secrethub.IteratorDone {
//	        break
//	    }
//	    if err != nil {
//	        // Handle error
//	    }
//
//      // Use event
//  }
func (s repoService) EventIterator(path string, options ...AuditEventIterationOption) (AuditEventIterator, error) {
	repoPath, err := api.NewRepoPath(path)
	if err != nil {
		return AuditEventIterator{}, errio.Error(err)
	}

	namespace, repoName := repoPath.GetNamespaceAndRepoName()
	paginator := s.client.httpClient.AuditRepoPaginator(namespace, repoName)

	res := newAuditEventIterator(paginator, s.client)

	for _, option := range options {
		err := option(&res)
		if err != nil {
			return AuditEventIterator{}, err
		}
	}

	return res, nil
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
