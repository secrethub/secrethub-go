package secrethub

import (
	"fmt"

	"github.com/secrethub/secrethub-go/internals/api"
	"github.com/secrethub/secrethub-go/internals/api/uuid"
	"github.com/secrethub/secrethub-go/internals/errio"
	"github.com/secrethub/secrethub-go/pkg/secrethub/iterator"
)

// AccessRuleService handles operations on access rules from SecretHub.
type AccessRuleService interface {
	// Get retrieves the access rule for the given account on the given directory.
	Get(path string, accountName string) (*api.AccessRule, error)
	// Set sets an access rule with a certain permission level for an account to a path.
	Set(path string, permission string, accountName string) (*api.AccessRule, error)
	// Delete removes the accessrule for the given directory and account.
	Delete(path string, accountName string) error
	// List retrieves all access rules that apply to a directory, including
	// rules that apply to its children up to a specified depth. When ancestors is set
	// to true, it also includes rules for any parent directories. When the depth is
	// set to -1, all children are retrieved without limit.
	// Deprecated: Use iterator function instead.
	List(path string, depth int, ancestors bool) ([]*api.AccessRule, error)
	// Iterator returns an iterator that retrieves all access rules that apply to a
	// directory.
	Iterator(path string, _ *AccessRuleIteratorParams) AccessRuleIterator
	// ListLevels lists the access levels on the given directory.
	// Deprecated: Use iterator function instead.
	ListLevels(path string) ([]*api.AccessLevel, error)
	// LevelIterator returns an iterator that retrieves all access levels on the given directory.
	LevelIterator(path string, _ *AccessLevelIteratorParams) AccessLevelIterator
}

// missingMemberRetries is the number of times creation of access rules is retried when
// encrypted members are missing in the request. Members to encrypt are fetched again this
// number of times and a new access rule create request is made.
// When creating access rules, missing members occur when secrets, secret keys, or directories
// were added between fetching the secrets, secret keys and directories to encrypt for the
// account for which the access rule is created and the request creating the access rule.
const missingMemberRetries = 3

func newAccessRuleService(client *Client) AccessRuleService {
	return accessRuleService{
		client:         client,
		accountService: newAccountService(client),
		dirService:     newDirService(client),
	}
}

type accessRuleService struct {
	client         *Client
	accountService AccountService
	dirService     DirService
}

// Delete removes the accessrule for the given directory and account.
func (s accessRuleService) Delete(path string, accountName string) error {
	p, err := api.NewDirPath(path)
	if err != nil {
		return errio.Error(err)
	}

	an, err := api.NewAccountName(accountName)
	if err != nil {
		return errio.Error(err)
	}

	blindName, err := s.client.convertPathToBlindName(p)
	if err != nil {
		return errio.Error(err)
	}

	err = s.client.httpClient.DeleteAccessRule(blindName, an)
	if err != nil {
		return errio.Error(err)
	}

	return nil
}

// Get retrieves the access rule for the given account on the given directory.
func (s accessRuleService) Get(path string, accountName string) (*api.AccessRule, error) {
	p, err := api.NewDirPath(path)
	if err != nil {
		return nil, errio.Error(err)
	}

	an, err := api.NewAccountName(accountName)
	if err != nil {
		return nil, errio.Error(err)
	}

	blindName, err := s.client.convertPathToBlindName(p)
	if err != nil {
		return nil, errio.Error(err)
	}

	accessRule, err := s.client.httpClient.GetAccessRule(blindName, an)
	if err != nil {
		return nil, errio.Error(err)
	}

	return accessRule, nil
}

// List retrieves all access rules that apply to a directory, including
// rules that apply to its children up to a specified depth. When ancestors is set
// to true, it also includes rules for any parent directories. When the depth is
// set to -1, all children are retrieved without limit.
func (s accessRuleService) List(path string, depth int, ancestors bool) ([]*api.AccessRule, error) {
	p, err := api.NewDirPath(path)
	if err != nil {
		return nil, errio.Error(err)
	}

	blindName, err := s.client.convertPathToBlindName(p)
	if err != nil {
		return nil, errio.Error(err)
	}

	rules, err := s.client.httpClient.ListAccessRules(blindName, depth, ancestors)
	if err != nil {
		return nil, errio.Error(err)
	}

	return rules, nil
}

// List lists the access rules on the given directory.
func (s accessRuleService) ListLevels(path string) ([]*api.AccessLevel, error) {
	p, err := api.NewDirPath(path)
	if err != nil {
		return nil, errio.Error(err)
	}

	blindName, err := s.client.convertPathToBlindName(p)
	if err != nil {
		return nil, errio.Error(err)
	}

	rules, err := s.client.httpClient.ListAccessRules(blindName, 0, true)
	if err != nil {
		return nil, errio.Error(err)
	}

	dir, err := s.dirService.GetTree(path, 0, false)
	if err != nil {
		return nil, errio.Error(err)
	}

	rights := make(map[uuid.UUID][]*api.AccessRule)
	for _, rule := range rules {
		list := rights[rule.AccountID]
		rights[rule.AccountID] = append(list, rule)
	}

	result := make([]*api.AccessLevel, len(rights))
	i := 0
	for _, list := range rights {
		first := list[0]
		maxPerm := first.Permission
		for _, rule := range list {
			if maxPerm < rule.Permission {
				maxPerm = rule.Permission
			}
		}

		result[i] = &api.AccessLevel{
			Account:    first.Account,
			AccountID:  first.AccountID,
			DirID:      dir.RootDir.DirID, // add this for completeness
			Permission: maxPerm,
		}

		i++
	}

	return result, nil
}

// Set sets an access rule with a certain permission level for an account to a path.
func (s accessRuleService) Set(path string, permission string, accountName string) (*api.AccessRule, error) {
	var perm api.Permission
	err := perm.Set(permission)
	if err != nil {
		return nil, err
	}

	p, err := api.NewDirPath(path)
	if err != nil {
		return nil, errio.Error(err)
	}

	an, err := api.NewAccountName(accountName)
	if err != nil {
		return nil, errio.Error(err)
	}

	_, err = s.Get(path, accountName)
	if err != nil && !api.IsErrNotFound(err) {
		return nil, errio.Error(err)
	} else if api.IsErrNotFound(err) {
		return s.create(p, perm, an)
	}
	return s.update(p, perm, an)
}

// CreateAccessRule creates a new AccessRule for an account with a certain permission level.
func (s accessRuleService) create(path api.BlindNamePath, permission api.Permission, accountName api.AccountName) (*api.AccessRule, error) {
	blindName, err := s.client.convertPathToBlindName(path)
	if err != nil {
		return nil, errio.Error(err)
	}

	account, err := s.accountService.Get(accountName.String())
	if err != nil {
		return nil, errio.Error(err)
	}

	currentAccessLevel, err := s.client.getAccessLevel(path, accountName)
	if err != nil {
		return nil, errio.Error(err)
	}

	in := &api.CreateAccessRuleRequest{
		Permission: permission,
	}

	encrypter := newReencrypter(account, s.client)

	tries := 0
	for {
		if currentAccessLevel.Permission < api.PermissionRead {
			err = encrypter.Add(blindName)
			if err != nil {
				return nil, err
			}

			in.EncryptedDirs = encrypter.Dirs()
			in.EncryptedSecrets = encrypter.Secrets()
		}
		err = in.Validate()
		if err != nil {
			return nil, err
		}

		accessRule, err := s.client.httpClient.CreateAccessRule(blindName, accountName, in)
		if err == nil {
			return accessRule, nil
		}
		if !errio.EqualsAPIError(api.ErrNotEncryptedForAccounts, err) {
			return nil, err
		}
		if tries >= missingMemberRetries {
			return nil, fmt.Errorf("cannot create access rule: resources controlled by the access rule are simultaneously being created; you may try again")
		}
		tries++
	}
}

func newReencrypter(encryptFor *api.Account, client *Client) *reencrypter {
	return &reencrypter{
		dirs:       make(map[uuid.UUID]api.EncryptedNameForNodeRequest),
		secrets:    make(map[uuid.UUID]api.SecretAccessRequest),
		encryptFor: encryptFor,
		client:     client,
	}
}

type reencrypter struct {
	dirs       map[uuid.UUID]api.EncryptedNameForNodeRequest
	secrets    map[uuid.UUID]api.SecretAccessRequest
	encryptFor *api.Account
	client     *Client
}

func (re *reencrypter) Add(blindName string) error {
	encryptedTree, err := re.client.httpClient.GetTree(blindName, -1, true)
	if err != nil {
		return err
	}

	accountKey, err := re.client.getAccountKey()
	if err != nil {
		return err
	}

	for _, dir := range encryptedTree.Directories {
		_, ok := re.dirs[dir.DirID]
		if !ok {
			decrypted, err := dir.Decrypt(accountKey)
			if err != nil {
				return err
			}
			encrypted, err := re.client.encryptDirFor(decrypted, re.encryptFor)
			if err != nil {
				return err
			}
			re.dirs[dir.DirID] = encrypted
		}
	}

	for _, secret := range encryptedTree.Secrets {
		_, ok := re.secrets[secret.SecretID]
		if !ok {
			decrypted, err := secret.Decrypt(accountKey)
			if err != nil {
				return err
			}
			encrypted, err := re.client.encryptSecretFor(decrypted, re.encryptFor)
			if err != nil {
				return err
			}
			re.secrets[secret.SecretID] = encrypted
		}
	}

	return nil
}

func (re *reencrypter) Secrets() []api.SecretAccessRequest {
	res := make([]api.SecretAccessRequest, len(re.secrets))
	i := 0
	for _, secret := range re.secrets {
		res[i] = secret
		i++
	}
	return res
}

func (re *reencrypter) Dirs() []api.EncryptedNameForNodeRequest {
	res := make([]api.EncryptedNameForNodeRequest, len(re.dirs))
	i := 0
	for _, dir := range re.dirs {
		res[i] = dir
		i++
	}
	return res
}

// UpdateAccessRule updates an AccessRule for an account with a certain permission level.
// It fails if the AccessRule does not already exist.
func (s accessRuleService) update(path api.BlindNamePath, permission api.Permission, name api.AccountName) (*api.AccessRule, error) {
	blindName, err := s.client.convertPathToBlindName(path)
	if err != nil {
		return nil, errio.Error(err)
	}

	in := &api.UpdateAccessRuleRequest{
		Permission: permission,
	}
	accessRule, err := s.client.httpClient.UpdateAccessRule(blindName, name, in)
	return accessRule, errio.Error(err)
}

// GetAccessLevel retrieves the permissions of an account on a directory, defined by
// one or more access rules on the directory itself or its parent(s).
func (c *Client) getAccessLevel(path api.BlindNamePath, accountName api.AccountName) (*api.AccessLevel, error) {
	blindName, err := c.convertPathToBlindName(path)
	if err != nil {
		return nil, errio.Error(err)
	}

	accessLevel, err := c.httpClient.GetAccessLevel(blindName, accountName)
	if err != nil {
		return nil, errio.Error(err)
	}

	return accessLevel, nil
}

// Iterator returns an iterator that retrieves all access rules that apply to a
// directory.
func (s accessRuleService) Iterator(path string, params *AccessRuleIteratorParams) AccessRuleIterator {
	if params == nil {
		params = &AccessRuleIteratorParams{}
	}

	depth := -1
	if params.Depth != nil {
		depth = int(*params.Depth)
	}
	ancestors := params.Ancestors

	return &accessRuleIterator{
		iterator: iterator.New(
			iterator.PaginatorFactory(
				func() ([]interface{}, error) {
					p, err := api.NewDirPath(path)
					if err != nil {
						return nil, errio.Error(err)
					}

					blindName, err := s.client.convertPathToBlindName(p)
					if err != nil {
						return nil, errio.Error(err)
					}

					accessRules, err := s.client.httpClient.ListAccessRules(blindName, depth, ancestors)
					if err != nil {
						return nil, errio.Error(err)
					}

					res := make([]interface{}, len(accessRules))
					for i, element := range accessRules {
						res[i] = element
					}
					return res, nil
				},
			),
		),
	}
}

// LevelIterator returns an iterator that retrieves all access levels on the given directory.
func (s accessRuleService) LevelIterator(path string, _ *AccessLevelIteratorParams) AccessLevelIterator {
	return &accessLevelIterator{
		iterator: iterator.New(
			iterator.PaginatorFactory(
				func() ([]interface{}, error) {
					p, err := api.NewDirPath(path)
					if err != nil {
						return nil, errio.Error(err)
					}

					blindName, err := s.client.convertPathToBlindName(p)
					if err != nil {
						return nil, errio.Error(err)
					}

					rules, err := s.client.httpClient.ListAccessRules(blindName, 0, true)
					if err != nil {
						return nil, errio.Error(err)
					}

					dir, err := s.dirService.GetTree(path, 0, false)
					if err != nil {
						return nil, errio.Error(err)
					}

					rights := make(map[uuid.UUID][]*api.AccessRule)
					for _, rule := range rules {
						list := rights[rule.AccountID]
						rights[rule.AccountID] = append(list, rule)
					}

					accessLevels := make([]*api.AccessLevel, len(rights))
					i := 0
					for _, list := range rights {
						first := list[0]
						maxPerm := first.Permission
						for _, rule := range list {
							if maxPerm < rule.Permission {
								maxPerm = rule.Permission
							}
						}

						accessLevels[i] = &api.AccessLevel{
							Account:    first.Account,
							AccountID:  first.AccountID,
							DirID:      dir.RootDir.DirID, // add this for completeness
							Permission: maxPerm,
						}

						i++
					}

					res := make([]interface{}, len(accessLevels))
					for i, element := range accessLevels {
						res[i] = element
					}
					return res, nil
				},
			),
		),
	}
}

// AccessLevelIterator iterates over access rules.
type AccessRuleIterator interface {
	Next() (api.AccessRule, error)
}

type accessRuleIterator struct {
	iterator iterator.Iterator
}

// Next returns the next access rule or iterator.Done if all of them have been returned.
func (it *accessRuleIterator) Next() (api.AccessRule, error) {
	item, err := it.iterator.Next()
	if err != nil {
		return api.AccessRule{}, err
	}

	return *item.(*api.AccessRule), nil
}

// AccessRuleIteratorParams specify parameters used when listing access rules.
type AccessRuleIteratorParams struct {
	Depth     *uint // Depth defines the depth of traversal for the iterator, nil means listing all subdirectories.
	Ancestors bool  // Ancestors defines whether the iterator should also list access rules of parent directories.
}

// AccessLevelIteratorParams defines the parameters used when listing access levels.
type AccessLevelIteratorParams struct{}

// AccessLevelIterator iterates over access levels.
type AccessLevelIterator interface {
	Next() (api.AccessLevel, error)
}

type accessLevelIterator struct {
	iterator iterator.Iterator
}

// Next returns the next access level or iterator.Done if all of them have been returned.
func (it *accessLevelIterator) Next() (api.AccessLevel, error) {
	item, err := it.iterator.Next()
	if err != nil {
		return api.AccessLevel{}, err
	}

	return *item.(*api.AccessLevel), nil
}
