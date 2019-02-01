package secrethub

import (
	"github.com/keylockerbv/secrethub-go/pkg/api"
	"github.com/keylockerbv/secrethub-go/pkg/crypto"
	"github.com/keylockerbv/secrethub-go/pkg/errio"
)

// RepoService handles operations on repositories from SecretHub.
type RepoService interface {
	// Create creates a new repo for the given owner and name.
	Create(path api.RepoPath) (*api.Repo, error)
	// Delete removes the repo with the given path.
	Delete(path api.RepoPath) error
	// Get retrieves the repo with the given path.
	Get(path api.RepoPath) (*api.Repo, error)
	// List retrieves all repositories in the given namespace.
	List(namespace api.Namespace) ([]*api.Repo, error)
	// ListAccounts lists the accounts in the repository.
	ListAccounts(path api.RepoPath) ([]*api.Account, error)
	// ListEvents retrieves all audit events for a given repo.
	ListEvents(path api.RepoPath, subjectTypes api.AuditSubjectTypeList) ([]*api.Audit, error)
	// ListMine retrieves all repositories of the current user.
	ListMine() ([]*api.Repo, error)
	// Users returns a RepoUserService that handles operations on users of a repository.
	Users() RepoUserService
	// Services returns a RepoServiceService that handles operations on services of a repository.
	Services() RepoServiceService
}

func newRepoService(client client) RepoService {
	return repoService{
		client: client,
	}
}

type repoService struct {
	client client
}

// Delete removes the repo with the given path.
func (s repoService) Delete(path api.RepoPath) error {
	return s.client.DeleteRepo(path)
}

// Get retrieves the repo with the given path.
func (s repoService) Get(path api.RepoPath) (*api.Repo, error) {
	return s.client.GetRepo(path)
}

// List retrieves all repositories in the given namespace.
func (s repoService) List(namespace api.Namespace) ([]*api.Repo, error) {
	return s.client.ListRepos(string(namespace))
}

// ListAccounts lists the accounts in the repository.
func (s repoService) ListAccounts(path api.RepoPath) ([]*api.Account, error) {
	return s.client.ListRepoAccounts(path)
}

// ListEvents retrieves all audit events for a given repo.
// If subjectTypes is left empty, the server's default is used.
func (s repoService) ListEvents(path api.RepoPath, subjectTypes api.AuditSubjectTypeList) ([]*api.Audit, error) {
	return s.client.ListAuditEventsRepo(path, subjectTypes)
}

// ListMine retrieves all repositories of the current user.
func (s repoService) ListMine() ([]*api.Repo, error) {
	return s.client.ListMyRepos()
}

// Create creates a new repo for the given owner and name.
func (s repoService) Create(path api.RepoPath) (*api.Repo, error) {
	return s.client.CreateRepo(path)
}

// Users returns a RepoUserService that handles operations on users of a repository.
func (s repoService) Users() RepoUserService {
	return newRepoUserService(s.client)
}

// Services returns a RepoServiceService that handles operations on services of a repository.
func (s repoService) Services() RepoServiceService {
	return newRepoServiceService(s.client)
}

// CreateRepo creates a new repo for this owner with the name.
func (c *client) CreateRepo(repoPath api.RepoPath) (*api.Repo, error) {
	err := repoPath.Validate()
	if err != nil {
		return nil, errio.Error(err)
	}

	account, err := c.getMyAccount()
	if err != nil {
		return nil, errio.Error(err)
	}

	accountKey, err := c.getAccountKey()
	if err != nil {
		return nil, errio.Error(err)
	}

	// Generate the repoEncryptionKey and wrap it.
	key, err := crypto.GenerateAESKey()
	if err != nil {
		return nil, errio.Error(err)
	}
	repoEncryptionKey, err := accountKey.Encrypt(key.Export())
	if err != nil {
		return nil, errio.Error(err)
	}

	// Generate repoIndexKey, repoBlindName and wrap it.
	key, err = crypto.GenerateAESKey()
	if err != nil {
		return nil, errio.Error(err)
	}

	repoIndexKey, err := accountKey.Encrypt(key.Export())
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
		Name: repoPath.GetRepo(),

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

	repo, err := c.httpClient.CreateRepo(repoPath.GetNamespace(), in)
	if err != nil {
		return nil, errio.Error(err)
	}

	return repo, nil
}

// DeleteRepo deletes a repo on the specified namespace with the name.
func (c *client) DeleteRepo(repoPath api.RepoPath) error {
	err := c.httpClient.DeleteRepo(repoPath.GetNamespaceAndRepoName())
	if err != nil {
		return errio.Error(err)
	}

	delete(c.repoIndexKeys, repoPath)

	return nil
}

// ListRepos lists the repos in a namespace the account has access to.
func (c *client) ListRepos(namespace string) ([]*api.Repo, error) {
	err := api.ValidateNamespace(namespace)
	if err != nil {
		return nil, errio.Error(err)
	}

	return c.httpClient.ListRepos(namespace)
}

// ListMyRepos lists the repos an account has access to.
func (c *client) ListMyRepos() ([]*api.Repo, error) {
	return c.httpClient.ListMyRepos()
}

// GetRepo retrieves the Repo from SecretHub.
func (c *client) GetRepo(repoPath api.RepoPath) (*api.Repo, error) {
	repo, err := c.httpClient.GetRepo(repoPath.GetNamespaceAndRepoName())
	if err != nil {
		return nil, errio.Error(err)
	}

	return repo, nil
}

// InviteRepo adds access for a given User for a given repo.
func (c *client) InviteRepo(repoPath api.RepoPath, username string) (*api.RepoMember, error) {
	name := api.AccountName(username)
	err := name.Validate()
	if err != nil {
		return nil, err
	}
	if !name.IsUser() {
		return nil, api.ErrUsernameIsService
	}

	account, err := c.httpClient.GetAccount(name)
	if err == api.ErrAccountNotFound {
		// return a more context specific error
		return nil, api.ErrUserNotFound
	} else if err != nil {
		return nil, errio.Error(err)
	}

	if len(account.PublicKey) == 0 {
		return nil, api.ErrAccountNotKeyed
	}

	createRepoMember, err := c.createRepoMemberRequest(repoPath, account.PublicKey)
	if err != nil {
		return nil, errio.Error(err)
	}

	in := &api.InviteUserRequest{
		AccountID:  account.AccountID,
		RepoMember: createRepoMember,
	}

	repoMember, err := c.httpClient.InviteRepo(repoPath.GetNamespace(), repoPath.GetRepo(), in)
	if err != nil {
		return nil, errio.Error(err)
	}

	return repoMember, nil
}

// GetRepoUser retrieves a User if it has access to a repo.
func (c *client) GetRepoUser(repoPath api.RepoPath, username string) (*api.User, error) {
	user, err := c.httpClient.GetRepoUser(repoPath.GetNamespace(), repoPath.GetRepo(), username)
	return user, errio.Error(err)
}

// RemoveUser removes access for a given User for a given repo.
func (c *client) RemoveUser(repoPath api.RepoPath, username string) (*api.RevokeRepoResponse, error) {
	resp, err := c.httpClient.RemoveUser(repoPath.GetNamespace(), repoPath.GetRepo(), username)
	if err != nil {
		return nil, errio.Error(err)
	}

	return resp, nil
}

// ListRepoAccounts lists all repo accounts in the repo.
func (c *client) ListRepoAccounts(repoPath api.RepoPath) ([]*api.Account, error) {
	accounts, err := c.httpClient.ListRepoAccounts(repoPath.GetNamespaceAndRepoName())
	if err != nil {
		return nil, errio.Error(err)
	}

	return accounts, nil
}

// ListRepoUsers lists all users with access to the Repo by RepoPath.
func (c *client) ListRepoUsers(repoPath api.RepoPath) ([]*api.User, error) {
	users, err := c.httpClient.ListRepoUsers(repoPath.GetNamespaceAndRepoName())
	if err != nil {
		return nil, errio.Error(err)
	}

	return users, nil
}

// ListRepoServices lists all services with access to the Repo by RepoPath.
func (c *client) ListRepoServices(repoPath api.RepoPath) ([]*api.Service, error) {
	services, err := c.httpClient.ListServices(repoPath.GetNamespaceAndRepoName())
	if err != nil {
		return nil, errio.Error(err)
	}

	return services, nil
}

// Creates a new RepoMemberRequests for a given account.
func (c *client) createRepoMemberRequest(repoPath api.RepoPath, accountPublicKey []byte) (*api.CreateRepoMemberRequest, error) {
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

	accountRepoEncryptionKey, err := accountKey.ReEncrypt(rsaPublicKey, repoKey.RepoEncryptionKey)
	if err != nil {
		return nil, errio.Error(err)
	}

	accountRepoIndexKey, err := accountKey.ReEncrypt(rsaPublicKey, repoKey.RepoIndexKey)
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
func (c *client) getRepoIndexKey(repoPath api.RepoPath) (*crypto.AESKey, error) {
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

	keyData, err := accountKey.Decrypt(wrappedKey.RepoIndexKey)
	if err != nil {
		return nil, errio.Error(err)
	}

	repoIndexKey = crypto.NewAESKey(keyData)

	c.repoIndexKeys[repoPath] = repoIndexKey

	return repoIndexKey, nil
}
