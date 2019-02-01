package secrethub

import (
	"github.com/keylockerbv/secrethub-go/pkg/api"
	"github.com/keylockerbv/secrethub-go/pkg/api/uuid"
	"github.com/keylockerbv/secrethub-go/pkg/errio"
)

// AccessRuleService handles operations on access rules from SecretHub.
type AccessRuleService interface {
	// Delete removes the accessrule for the given directory and account.
	Delete(path api.DirPath, accountName api.AccountName) error
	// Get retrieves the access rule for the given account on the given directory.
	Get(path api.DirPath, accountName api.AccountName) (*api.AccessRule, error)
	// List retrieves all access rules that apply to a directory.
	List(path api.DirPath, depth int, ancestors bool) ([]*api.AccessRule, error)
	// ListWithPaths retrieves all access rules that apply to a directory,
	// mapped to their respective paths, including rules that apply to its children
	// up to a specified depth. When ancestors is set to true, it also includes rules
	// for any parent directories. When the depth is set to -1, all children are
	// retrieved without limit.
	ListWithPaths(path api.DirPath, depth int, ancestors bool) (map[api.DirPath][]*api.AccessRule, error)
	// List lists the access levels on the given directory.
	ListLevels(apth api.DirPath) ([]*api.AccessLevel, error)
	// Set sets an access rule with a certain permission level for an account to a path.
	Set(path api.DirPath, permission api.Permission, name api.AccountName) (*api.AccessRule, error)
}

func newAccessRuleService(client client) AccessRuleService {
	return accessRuleService{
		client: client,
	}
}

type accessRuleService struct {
	client client
}

// Delete removes the accessrule for the given directory and account.
func (s accessRuleService) Delete(path api.DirPath, accountName api.AccountName) error {
	return s.client.DeleteAccessRule(path, accountName)
}

// Get retrieves the access rule for the given account on the given directory.
func (s accessRuleService) Get(path api.DirPath, accountName api.AccountName) (*api.AccessRule, error) {
	return s.client.GetAccessRule(path, accountName)
}

// List retrieves all access rules that apply to a directory.
func (s accessRuleService) List(path api.DirPath, depth int, ancestors bool) ([]*api.AccessRule, error) {
	return s.client.ListAccessRules(path, depth, ancestors)
}

// ListWithPaths retrieves all access rules that apply to a directory,
// mapped to their respective paths, including rules that apply to its children
// up to a specified depth. When ancestors is set to true, it also includes rules
// for any parent directories. When the depth is set to -1, all children are
// retrieved without limit.
func (s accessRuleService) ListWithPaths(path api.DirPath, depth int, ancestors bool) (map[api.DirPath][]*api.AccessRule, error) {
	return s.client.ListAccessRulesWithPaths(path, depth, ancestors)
}

// List lists the access rules on the given directory.
func (s accessRuleService) ListLevels(path api.DirPath) ([]*api.AccessLevel, error) {
	return s.client.ListAccessLevels(path)
}

// Set sets an access rule with a certain permission level for an account to a path.
func (s accessRuleService) Set(path api.DirPath, permission api.Permission, name api.AccountName) (*api.AccessRule, error) {
	return s.client.SetAccessRule(path, permission, name)
}

// SetAccessRule set an AccessRule for an account with a certain permission level.
// If the AccessRule did not exist, it is created.
func (c *client) SetAccessRule(path api.BlindNamePath, permission api.Permission, name api.AccountName) (*api.AccessRule, error) {
	err := api.ValidateAccountName(name)
	if err != nil {
		return nil, errio.Error(err)
	}

	_, err = c.GetAccessRule(path, name)
	if err != nil && err != api.ErrAccessRuleNotFound {
		return nil, errio.Error(err)
	} else if err == api.ErrAccessRuleNotFound {
		return c.CreateAccessRule(path, permission, name)
	}
	return c.UpdateAccessRule(path, permission, name)
}

// CreateAccessRule creates a new AccessRule for an account with a certain permission level.
func (c *client) CreateAccessRule(path api.BlindNamePath, permission api.Permission, accountName api.AccountName) (*api.AccessRule, error) {
	blindName, err := c.convertPathToBlindName(path)
	if err != nil {
		return nil, errio.Error(err)
	}

	err = api.ValidateAccountName(accountName)
	if err != nil {
		return nil, errio.Error(err)
	}

	account, err := c.GetAccount(accountName)
	if err != nil {
		return nil, errio.Error(err)
	}

	currentAccessLevel, err := c.GetAccessLevel(path, accountName)
	if err != nil {
		return nil, errio.Error(err)
	}

	in := &api.CreateAccessRuleRequest{
		Permission: permission,
	}

	if currentAccessLevel.Permission < api.PermissionRead {
		encryptedTree, err := c.httpClient.GetTree(blindName, -1, true)
		if err != nil {
			return nil, errio.Error(err)
		}

		accountKey, err := c.getAccountKey()
		if err != nil {
			return nil, errio.Error(err)
		}

		dirs, secrets, err := encryptedTree.DecryptContents(accountKey)
		if err != nil {
			return nil, errio.Error(err)
		}

		in.EncryptedDirs = make([]api.EncryptedNameForNodeRequest, 0, len(dirs))
		for _, dir := range dirs {
			encryptedDirs, err := c.encryptDirFor(dir, account)
			if err != nil {
				return nil, errio.Error(err)
			}
			in.EncryptedDirs = append(in.EncryptedDirs, encryptedDirs...)
		}

		in.EncryptedSecrets = make([]api.SecretAccessRequest, 0, len(secrets))
		for _, secret := range secrets {
			encryptedSecrets, err := c.encryptSecretFor(secret, account)
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

	accessRule, err := c.httpClient.CreateAccessRule(blindName, accountName, in)
	return accessRule, errio.Error(err)

}

// UpdateAccessRule updates an AccessRule for an account with a certain permission level.
// It fails if the AccessRule does not already exist.
func (c *client) UpdateAccessRule(path api.BlindNamePath, permission api.Permission, name api.AccountName) (*api.AccessRule, error) {
	blindName, err := c.convertPathToBlindName(path)
	if err != nil {
		return nil, errio.Error(err)
	}

	err = api.ValidateAccountName(name)
	if err != nil {
		return nil, errio.Error(err)
	}

	in := &api.UpdateAccessRuleRequest{
		Permission: permission,
	}
	accessRule, err := c.httpClient.UpdateAccessRule(blindName, name, in)
	return accessRule, errio.Error(err)
}

// GetAccessLevel retrieves the permissions of an account on a directory, defined by
// one or more access rules on the directory itself or its parent(s).
func (c *client) GetAccessLevel(path api.BlindNamePath, accountName api.AccountName) (*api.AccessLevel, error) {
	blindName, err := c.convertPathToBlindName(path)
	if err != nil {
		return nil, errio.Error(err)
	}

	err = api.ValidateAccountName(accountName)
	if err != nil {
		return nil, errio.Error(err)
	}

	accessLevel, err := c.httpClient.GetAccessLevel(blindName, accountName)
	if err != nil {
		return nil, errio.Error(err)
	}

	return accessLevel, nil
}

// GetAccessRule returns the AccessRule for a path and an accountName, if it exists.
func (c *client) GetAccessRule(path api.BlindNamePath, accountName api.AccountName) (*api.AccessRule, error) {
	blindName, err := c.convertPathToBlindName(path)
	if err != nil {
		return nil, errio.Error(err)
	}

	err = api.ValidateAccountName(accountName)
	if err != nil {
		return nil, errio.Error(err)
	}

	accessRule, err := c.httpClient.GetAccessRule(blindName, accountName)
	if err != nil {
		return nil, errio.Error(err)
	}

	return accessRule, nil
}

// ListAccessRules retrieves all access rules that apply to a directory, including
// rules that apply to its children up to a specified depth. When ancestors is set
// to true, it also includes rules for any parent directories. When the depth is
// set to -1, all children are retrieved without limit.
func (c *client) ListAccessRules(path api.DirPath, depth int, ancestors bool) ([]*api.AccessRule, error) {
	blindName, err := c.convertPathToBlindName(path)
	if err != nil {
		return nil, errio.Error(err)
	}

	rules, err := c.httpClient.ListAccessRules(blindName, depth, ancestors)
	if err != nil {
		return nil, errio.Error(err)
	}

	return rules, nil
}

// ListAccessRulesWithPaths retrieves all access rules that apply to a directory,
// mapped to their respective paths, including rules that apply to its children
// up to a specified depth. When ancestors is set to true, it also includes rules
// for any parent directories. When the depth is set to -1, all children are
// retrieved without limit.
func (c *client) ListAccessRulesWithPaths(path api.DirPath, depth int, ancestors bool) (map[api.DirPath][]*api.AccessRule, error) {
	rules, err := c.ListAccessRules(path, depth, ancestors)
	if err != nil {
		return nil, errio.Error(err)
	}

	dirFS, err := c.GetDirByBlindName(path, depth, ancestors)
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

		result[*dirPath] = dirRules
	}

	return result, nil
}

// ListAccessLevels determines the access rights of all accounts on a directory,
// defined by the access rules on the directory itself or on its parent(s).
func (c *client) ListAccessLevels(path api.DirPath) ([]*api.AccessLevel, error) {
	blindName, err := c.convertPathToBlindName(path)
	if err != nil {
		return nil, errio.Error(err)
	}

	rules, err := c.httpClient.ListAccessRules(blindName, 0, true)
	if err != nil {
		return nil, errio.Error(err)
	}

	dir, err := c.GetDirByBlindName(path, 0, false)
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

// DeleteAccessRule deletes the AccessRule for a path and an accountName.
func (c *client) DeleteAccessRule(path api.BlindNamePath, accountName api.AccountName) error {
	blindName, err := c.convertPathToBlindName(path)
	if err != nil {
		return errio.Error(err)
	}

	err = accountName.Validate()
	if err != nil {
		return errio.Error(err)
	}

	err = c.httpClient.DeleteAccessRule(blindName, accountName)
	if err != nil {
		return errio.Error(err)
	}

	return nil
}
