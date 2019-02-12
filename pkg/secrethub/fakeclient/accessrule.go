// +build !production

package fakeclient

import "github.com/keylockerbv/secrethub-go/pkg/api"

// AccessRuleService is a mock of the AccessRuleService interface.
type AccessRuleService struct {
	DeleteFunc        func(path api.DirPath, accountName api.AccountName) error
	GetFunc           func(path api.DirPath, accountName api.AccountName) (*api.AccessRule, error)
	ListLevelsFunc    func(path api.DirPath) ([]*api.AccessLevel, error)
	ListFunc          func(path api.DirPath, depth int, ancestors bool) ([]*api.AccessRule, error)
	ListWithPathsFunc func(path api.DirPath, depth int, ancestors bool) (map[api.DirPath][]*api.AccessRule, error)
	SetFunc           func(path api.DirPath, permission api.Permission, name api.AccountName) (*api.AccessRule, error)
}

// Delete implements the AccessRuleService interface Delete function.
func (s AccessRuleService) Delete(path api.DirPath, accountName api.AccountName) error {
	return s.DeleteFunc(path, accountName)
}

// Get implements the AccessRuleService interface Get function.
func (s AccessRuleService) Get(path api.DirPath, accountName api.AccountName) (*api.AccessRule, error) {
	return s.GetFunc(path, accountName)
}

// ListLevels implements the AccessRuleService interface ListLevels function.
func (s AccessRuleService) ListLevels(path api.DirPath) ([]*api.AccessLevel, error) {
	return s.ListLevelsFunc(path)
}

// List implements the AccessRuleService interface List function.
func (s AccessRuleService) List(path api.DirPath, depth int, ancestors bool) ([]*api.AccessRule, error) {
	return s.ListFunc(path, depth, ancestors)
}

// ListWithPaths implements the AccessRuleService interface ListWithPaths function.
func (s AccessRuleService) ListWithPaths(path api.DirPath, depth int, ancestors bool) (map[api.DirPath][]*api.AccessRule, error) {
	return s.ListWithPathsFunc(path, depth, ancestors)
}

// Set implements the AccessRuleService interface Set function.
func (s AccessRuleService) Set(path api.DirPath, permission api.Permission, name api.AccountName) (*api.AccessRule, error) {
	return s.SetFunc(path, permission, name)
}
