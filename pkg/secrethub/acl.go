package secrethub

import (
	"github.com/keylockerbv/secrethub-go/pkg/api"
	"github.com/keylockerbv/secrethub-go/pkg/api/uuid"
	"github.com/keylockerbv/secrethub-go/pkg/errio"
)

// AccessRuleService handles operations on access rules from SecretHub.
type AccessRuleService interface {
	// Delete removes the accessrule for the given directory and account.
	Delete(path string, accountName string) error
	// Get retrieves the access rule for the given account on the given directory.
	Get(path string, accountName string) (*api.AccessRule, error)
	// List retrieves all access rules that apply to a directory.
	List(path string, depth int, ancestors bool) ([]*api.AccessRule, error)
	// ListWithPaths retrieves all access rules that apply to a directory,
	// mapped to their respective paths, including rules that apply to its children
	// up to a specified depth. When ancestors is set to true, it also includes rules
	// for any parent directories. When the depth is set to -1, all children are
	// retrieved without limit.
	ListWithPaths(path string, depth int, ancestors bool) (map[api.DirPath][]*api.AccessRule, error)
	// ListLevels lists the access levels on the given directory.
	ListLevels(path string) ([]*api.AccessLevel, error)
	// Set sets an access rule with a certain permission level for an account to a path.
	Set(path string, permission api.Permission, accountName string) (*api.AccessRule, error)
}

func newAccessRuleService(client client) AccessRuleService {
	return accessRuleService{
		client:         client,
		accountService: newAccountService(client),
		dirService:     newDirService(client),
	}
}

type accessRuleService struct {
	client         client
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

// List etrieves all access rules that apply to a directory, including
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

// ListWithPaths retrieves all access rules that apply to a directory,
// mapped to their respective paths, including rules that apply to its children
// up to a specified depth. When ancestors is set to true, it also includes rules
// for any parent directories. When the depth is set to -1, all children are
// retrieved without limit.
func (s accessRuleService) ListWithPaths(path string, depth int, ancestors bool) (map[api.DirPath][]*api.AccessRule, error) {
	rules, err := s.List(path, depth, ancestors)
	if err != nil {
		return nil, errio.Error(err)
	}

	err = api.ValidateDirPath(path)
	if err != nil {
		return nil, errio.Error(err)
	}

	dirFS, err := s.dirService.GetTree(path, depth, ancestors)
	if err != nil {
		return nil, errio.Error(err)
	}

	// Separate all rules into lists of rules per directory.
	ruleMap := make(map[uuid.UUID][]int)
	for i, rule := range rules {
		list := ruleMap[*rule.DirID]
		ruleMap[*rule.DirID] = append(list, i)
	}

	// Map the directories to rule lists.
	result := make(map[api.DirPath][]*api.AccessRule)
	for dirID, list := range ruleMap {
		dirPath, err := dirFS.AbsDirPath(&dirID)
		if err != nil {
			return nil, errio.Error(err)
		}

		dirRules := make([]*api.AccessRule, len(list))
		for i, ruleIndex := range list {
			dirRules[i] = rules[ruleIndex]
		}

		result[dirPath] = dirRules
	}

	return result, nil
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
		list := rights[*rule.AccountID]
		rights[*rule.AccountID] = append(list, rule)
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
func (s accessRuleService) Set(path string, permission api.Permission, accountName string) (*api.AccessRule, error) {
	p, err := api.NewDirPath(path)
	if err != nil {
		return nil, errio.Error(err)
	}

	an, err := api.NewAccountName(accountName)
	if err != nil {
		return nil, errio.Error(err)
	}

	_, err = s.Get(path, accountName)
	if err != nil && err != api.ErrAccessRuleNotFound {
		return nil, errio.Error(err)
	} else if err == api.ErrAccessRuleNotFound {
		return s.create(p, permission, an)
	}
	return s.update(p, permission, an)
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

	if currentAccessLevel.Permission < api.PermissionRead {
		encryptedTree, err := s.client.httpClient.GetTree(blindName, -1, true)
		if err != nil {
			return nil, errio.Error(err)
		}

		accountKey, err := s.client.getAccountKey()
		if err != nil {
			return nil, errio.Error(err)
		}

		dirs, secrets, err := encryptedTree.DecryptContents(accountKey)
		if err != nil {
			return nil, errio.Error(err)
		}

		in.EncryptedDirs = make([]api.EncryptedNameForNodeRequest, 0, len(dirs))
		for _, dir := range dirs {
			encryptedDirs, err := s.client.encryptDirFor(dir, account)
			if err != nil {
				return nil, errio.Error(err)
			}
			in.EncryptedDirs = append(in.EncryptedDirs, encryptedDirs...)
		}

		in.EncryptedSecrets = make([]api.SecretAccessRequest, 0, len(secrets))
		for _, secret := range secrets {
			encryptedSecrets, err := s.client.encryptSecretFor(secret, account)
			if err != nil {
				return nil, errio.Error(err)
			}
			in.EncryptedSecrets = append(in.EncryptedSecrets, encryptedSecrets...)

		}
	}

	err = in.Validate()
	if err != nil {
		return nil, err
	}

	accessRule, err := s.client.httpClient.CreateAccessRule(blindName, accountName, in)
	return accessRule, errio.Error(err)

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
func (c *client) getAccessLevel(path api.BlindNamePath, accountName api.AccountName) (*api.AccessLevel, error) {
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
